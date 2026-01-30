"""
cron: 0 */6 * * *
new Env("Linux.Do 签到")
"""

import os
import random
import time
import functools
import sys
import re
from loguru import logger
from DrissionPage import ChromiumOptions, Chromium
from tabulate import tabulate
from curl_cffi import requests
from bs4 import BeautifulSoup


def retry_decorator(retries=3, min_delay=5, max_delay=10):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == retries - 1:  # 最后一次尝试
                        logger.error(f"函数 {func.__name__} 最终执行失败: {str(e)}")
                    logger.warning(
                        f"函数 {func.__name__} 第 {attempt + 1}/{retries} 次尝试失败: {str(e)}"
                    )
                    if attempt < retries - 1:
                        sleep_s = random.uniform(min_delay, max_delay)
                        logger.info(
                            f"将在 {sleep_s:.2f}s 后重试 ({min_delay}-{max_delay}s 随机延迟)"
                        )
                        time.sleep(sleep_s)
            return None

        return wrapper

    return decorator


os.environ.pop("DISPLAY", None)
os.environ.pop("DYLD_LIBRARY_PATH", None)

USERNAME = os.environ.get("LINUXDO_USERNAME")
PASSWORD = os.environ.get("LINUXDO_PASSWORD")
BROWSE_ENABLED = os.environ.get("BROWSE_ENABLED", "true").strip().lower() not in [
    "false",
    "0",
    "off",
]
if not USERNAME:
    USERNAME = os.environ.get("USERNAME")
if not PASSWORD:
    PASSWORD = os.environ.get("PASSWORD")
GOTIFY_URL = os.environ.get("GOTIFY_URL")  # Gotify 服务器地址
GOTIFY_TOKEN = os.environ.get("GOTIFY_TOKEN")  # Gotify 应用的 API Token
SC3_PUSH_KEY = os.environ.get("SC3_PUSH_KEY")  # Server酱³ SendKey
WXPUSH_URL = os.environ.get("WXPUSH_URL")  # wxpush 服务器地址
WXPUSH_TOKEN = os.environ.get("WXPUSH_TOKEN")  # wxpush 的 token

HOME_URL = "https://linux.do/"
LOGIN_URL = "https://linux.do/login"
SESSION_URL = "https://linux.do/session"
CSRF_URL = "https://linux.do/session/csrf"


class LinuxDoBrowser:
    def __init__(self) -> None:
        from sys import platform

        if platform == "linux" or platform == "linux2":
            platformIdentifier = "X11; Linux x86_64"
        elif platform == "darwin":
            platformIdentifier = "Macintosh; Intel Mac OS X 10_15_7"
        elif platform == "win32":
            platformIdentifier = "Windows NT 10.0; Win64; x64"
        else:
            platformIdentifier = "X11; Linux x86_64"

        co = (
            ChromiumOptions()
            .headless(True)
            .incognito(True)
            .set_argument("--no-sandbox")
        )
        co.set_user_agent(
            f"Mozilla/5.0 ({platformIdentifier}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        )
        self.browser = Chromium(co)
        self.page = self.browser.new_tab()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )

    def login(self):
        logger.info("开始登录流程")
        
        # --- 方案 A: 优先尝试 Cookie 登录 (推荐，可绕过 Cloudflare) ---
        cookie_str = os.environ.get("LINUXDO_COOKIE")
        if cookie_str:
            logger.info("检测到 LINUXDO_COOKIE，尝试通过 Cookie 直接登录...")
            
            # 1. 设置 Requests Session 的 Cookie
            # 简单的 Cookie 字符串解析
            for item in cookie_str.split(';'):
                if '=' in item:
                    k, v = item.strip().split('=', 1)
                    self.session.cookies.set(k, v, domain=".linux.do")
            
            # 2. 同步 Cookie 到 DrissionPage
            # DrissionPage 需要 list[dict] 格式
            dp_cookies = []
            for name, value in self.session.cookies.items():
                dp_cookies.append({
                    "name": name,
                    "value": value,
                    "domain": ".linux.do",
                    "path": "/",
                })
            self.page.set.cookies(dp_cookies)
            
            # 3. 验证是否有效
            logger.info("Cookie 设置完成，直接验证登录状态...")
            self.page.get(HOME_URL)
            time.sleep(3) # 等待页面加载
            
            if self._check_login_success():
                return True
            else:
                logger.error("提供的 Cookie 无效或已过期，尝试回退到账号密码登录...")
                # 如果 Cookie 失效，清理掉，防止干扰后续流程
                self.session.cookies.clear()
                self.page.delete_cookies()

        # --- 方案 B: 账号密码登录 (在 GitHub Actions 上极大概率被 CF 拦截) ---
        logger.info("尝试使用账号密码登录...")
        
        # Step 1: Get CSRF Token
        logger.info("获取 CSRF token...")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": LOGIN_URL,
        }
        
        try:
            # 增加 timeout 防止卡死
            resp_csrf = self.session.get(CSRF_URL, headers=headers, impersonate="chrome124", timeout=20)
            
            # 检查是否被 CF 拦截
            if resp_csrf.status_code == 403 or "<title>Just a moment...</title>" in resp_csrf.text:
                logger.error("❌ 严重错误: 请求被 Cloudflare 拦截 (403 Forbidden)。")
                logger.error("💡 建议: GitHub Actions IP 信誉过低。请配置 'LINUXDO_COOKIE' 使用 Cookie 模式绕过登录接口。")
                return False

            csrf_data = resp_csrf.json()
            csrf_token = csrf_data.get("csrf")
        except Exception as e:
            logger.error(f"获取 CSRF 失败: {str(e)}")
            return False

        # Step 2: Login Post
        logger.info(f"CSRF Token obtained. 正在提交登录表单...")
        headers.update({
            "X-CSRF-Token": csrf_token,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": "https://linux.do",
        })

        data = {
            "login": USERNAME,
            "password": PASSWORD,
            "second_factor_method": "1",
            "timezone": "Asia/Shanghai",
        }

        try:
            resp_login = self.session.post(
                SESSION_URL, data=data, impersonate="chrome124", headers=headers
            )
            
            if resp_login.status_code != 200:
                logger.error(f"登录 API 返回错误码: {resp_login.status_code}")
                return False
                
            resp_json = resp_login.json()
            if "error" in resp_json:
                logger.error(f"登录失败: {resp_json['error']}")
                return False
                
            logger.info("API 登录成功，同步 Cookie...")
            
            # 同步 Session Cookie 到 DrissionPage (原逻辑)
            cookies_dict = self.session.cookies.get_dict()
            dp_cookies = []
            for name, value in cookies_dict.items():
                dp_cookies.append({"name": name, "value": value, "domain": ".linux.do", "path": "/"})
            self.page.set.cookies(dp_cookies)
            
            self.page.get(HOME_URL)
            time.sleep(5)
            return self._check_login_success()

        except Exception as e:
            logger.error(f"登录过程发生异常: {e}")
            return False

    def _check_login_success(self):
        """辅助方法：检查页面元素判断是否登录成功"""
        try:
            # 检查头像或特定用户元素
            if self.page.ele("@id=current-user", timeout=2):
                logger.success("✅ 登录验证成功 (发现 current-user)")
                return True
            if "avatar" in self.page.html:
                logger.success("✅ 登录验证成功 (发现 avatar)")
                return True
            
            logger.warning("⚠️ 登录验证失败 (未找到用户标识)")
            # 截图调试 (GitHub Actions 可在 Artifacts 查看，如果你配置了上传)
            # self.page.get_screenshot(path="debug_login.png") 
            return False
        except Exception as e:
            logger.warning(f"验证过程异常: {e}")
            return False

    def click_topic(self):
        topic_list = self.page.ele("@id=list-area").eles(".:title")
        if not topic_list:
            logger.error("未找到主题帖")
            return False
        logger.info(f"发现 {len(topic_list)} 个主题帖，随机选择10个")
        for topic in random.sample(topic_list, 10):
            self.click_one_topic(topic.attr("href"))
        return True

    @retry_decorator()
    def click_one_topic(self, topic_url):
        new_page = self.browser.new_tab()
        try:
            new_page.get(topic_url)
            if random.random() < 0.3:  # 0.3 * 30 = 9
                self.click_like(new_page)
            self.browse_post(new_page)
        finally:
            try:
                new_page.close()
            except Exception:
                pass

    def browse_post(self, page):
        prev_url = None
        # 开始自动滚动，最多滚动10次
        for _ in range(10):
            # 随机滚动一段距离
            scroll_distance = random.randint(550, 650)  # 随机滚动 550-650 像素
            logger.info(f"向下滚动 {scroll_distance} 像素...")
            page.run_js(f"window.scrollBy(0, {scroll_distance})")
            logger.info(f"已加载页面: {page.url}")

            if random.random() < 0.03:  # 33 * 4 = 132
                logger.success("随机退出浏览")
                break

            # 检查是否到达页面底部
            at_bottom = page.run_js(
                "window.scrollY + window.innerHeight >= document.body.scrollHeight"
            )
            current_url = page.url
            if current_url != prev_url:
                prev_url = current_url
            elif at_bottom and prev_url == current_url:
                logger.success("已到达页面底部，退出浏览")
                break

            # 动态随机等待
            wait_time = random.uniform(2, 4)  # 随机等待 2-4 秒
            logger.info(f"等待 {wait_time:.2f} 秒...")
            time.sleep(wait_time)

    def run(self):
        try:
            login_res = self.login()
            if not login_res:  # 登录
                logger.warning("登录验证失败")

            if BROWSE_ENABLED:
                click_topic_res = self.click_topic()  # 点击主题
                if not click_topic_res:
                    logger.error("点击主题失败，程序终止")
                    return
                logger.info("完成浏览任务")

            self.send_notifications(BROWSE_ENABLED)  # 发送通知
        finally:
            try:
                self.page.close()
            except Exception:
                pass
            try:
                self.browser.quit()
            except Exception:
                pass

    def click_like(self, page):
        try:
            # 专门查找未点赞的按钮
            like_button = page.ele(".discourse-reactions-reaction-button")
            if like_button:
                logger.info("找到未点赞的帖子，准备点赞")
                like_button.click()
                logger.info("点赞成功")
                time.sleep(random.uniform(1, 2))
            else:
                logger.info("帖子可能已经点过赞了")
        except Exception as e:
            logger.error(f"点赞失败: {str(e)}")

    def print_connect_info(self):
        logger.info("获取连接信息")
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        }
        resp = self.session.get(
            "https://connect.linux.do/", headers=headers, impersonate="chrome136"
        )
        soup = BeautifulSoup(resp.text, "html.parser")
        rows = soup.select("table tr")
        info = []

        for row in rows:
            cells = row.select("td")
            if len(cells) >= 3:
                project = cells[0].text.strip()
                current = cells[1].text.strip() if cells[1].text.strip() else "0"
                requirement = cells[2].text.strip() if cells[2].text.strip() else "0"
                info.append([project, current, requirement])

        print("--------------Connect Info-----------------")
        print(tabulate(info, headers=["项目", "当前", "要求"], tablefmt="pretty"))

    def send_notifications(self, browse_enabled):
        status_msg = f"✅每日登录成功: {USERNAME}"
        if browse_enabled:
            status_msg += " + 浏览任务完成"

        if GOTIFY_URL and GOTIFY_TOKEN:
            try:
                response = requests.post(
                    f"{GOTIFY_URL}/message",
                    params={"token": GOTIFY_TOKEN},
                    json={"title": "LINUX DO", "message": status_msg, "priority": 1},
                    timeout=10,
                )
                response.raise_for_status()
                logger.success("消息已推送至Gotify")
            except Exception as e:
                logger.error(f"Gotify推送失败: {str(e)}")
        else:
            logger.info("未配置Gotify环境变量，跳过通知发送")

        if SC3_PUSH_KEY:
            match = re.match(r"sct(\d+)t", SC3_PUSH_KEY, re.I)
            if not match:
                logger.error(
                    "❌ SC3_PUSH_KEY格式错误，未获取到UID，无法使用Server酱³推送"
                )
                return

            uid = match.group(1)
            url = f"https://{uid}.push.ft07.com/send/{SC3_PUSH_KEY}"
            params = {"title": "LINUX DO", "desp": status_msg}

            attempts = 5
            for attempt in range(attempts):
                try:
                    response = requests.get(url, params=params, timeout=10)
                    response.raise_for_status()
                    logger.success(f"Server酱³推送成功: {response.text}")
                    break
                except Exception as e:
                    logger.error(f"Server酱³推送失败: {str(e)}")
                    if attempt < attempts - 1:
                        sleep_time = random.randint(180, 360)
                        logger.info(f"将在 {sleep_time} 秒后重试...")
                        time.sleep(sleep_time)

        if WXPUSH_URL and WXPUSH_TOKEN:
            try:
                response = requests.post(
                    f"{WXPUSH_URL}/wxsend",
                    headers={
                        "Authorization": WXPUSH_TOKEN,
                        "Content-Type": "application/json",
                    },
                    json={"title": "LINUX DO", "content": status_msg},
                    timeout=10,
                )
                response.raise_for_status()
                logger.success(f"wxpush 推送成功: {response.text}")
            except Exception as e:
                logger.error(f"wxpush 推送失败: {str(e)}")
        else:
            logger.info("未配置 WXPUSH_URL 或 WXPUSH_TOKEN，跳过通知发送")


if __name__ == "__main__":
    if not USERNAME or not PASSWORD:
        print("Please set USERNAME and PASSWORD")
        exit(1)
    l = LinuxDoBrowser()
    l.run()
