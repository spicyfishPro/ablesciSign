#!/usr/bin/env python
# cron:40 7,21 * * *
# new Env("科研通签到")
# coding=utf-8

"""
AbleSci自动签到脚本 
创建日期：2025年8月8日
更新日期：2025年9月2日 >> 修复日志输出时间为北京时间 ; 修复签到前后用户信息显示 ; 优化登录失败处理 ; 优化签到已签到处理
更新日期：2025年9月3日 >> 保护隐私，不在日志中显示完整邮箱和用户名
更新日期：2026年3月22日 >> 支持本地.env文件; 使用zoneinfo/pytz处理时区; 统一通知器; 修复zoneinfo时区查找失败问题,增加回退机制; 修复已签到处理逻辑; 
更新日期：2026年10月4日 >> 使用邮箱正则作为锚点解析账号，保留逗号/分号分隔多账号的旧格式，
                        同时避免密码中的逗号/分号被误拆；移除所有可能泄露明文密码的日志打印
作者：daitcl
"""

import os
import re
import sys
import time
import requests
from bs4 import BeautifulSoup
import json
import datetime
from pathlib import Path
from datetime import timezone, timedelta
from dataclasses import dataclass


try:
    from zoneinfo import ZoneInfo
    ZONEINFO_AVAILABLE = True
except ImportError:
    ZONEINFO_AVAILABLE = False

# 环境变量名常量
ENV_ACCOUNTS = "ABLESCI_ACCOUNTS"

# 邮箱匹配正则（用于识别账号锚点，避免按逗号/分号拆分时误伤密码）
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')


@dataclass(frozen=True)
class AccountResult:
    """账号结果只保存脱敏账号，不保存凭据或响应正文。"""
    account: str
    status: str  # signed / already_signed / failed
    reason: str = ""

    @property
    def ok(self):
        return self.status in ("signed", "already_signed")


FAILURE_LABELS = {
    "csrf_missing": "无法读取 CSRF 令牌，登录页结构可能已变更",
    "captcha_required": "需要人工完成图片验证",
    "captcha_invalid": "图片验证码错误或已失效，需要人工验证",
    "captcha_unavailable": "图片验证码服务暂时不可用",
    "rate_limited": "请求受到限流，请稍后重试",
    "login_failed": "登录失败",
    "sign_failed": "签到失败",
    "invalid_response": "服务端响应格式异常",
    "http_error": "服务端返回异常 HTTP 状态",
    "timeout": "请求超时",
    "network_error": "网络请求失败",
    "unexpected_error": "账号处理发生异常",
}


def response_failure(payload, status_code=200):
    """与当前登录页 bridge.js 使用相同的验证码标记。"""
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    if not isinstance(data, dict):
        data = {}
    error_code = data.get("error_code")
    if error_code == "CAPTCHA_UNAVAILABLE":
        return "captcha_unavailable"
    if error_code == "CAPTCHA_INVALID":
        return "captcha_invalid"
    if (error_code == "CAPTCHA_REQUIRED" or data.get("captcha_required")
            or str(data.get("verify", "")) == "1"):
        return "captcha_required"
    if status_code == 429 or error_code == "RATE_LIMITED":
        return "rate_limited"
    return ""


def already_signed(message):
    return (isinstance(message, str)
            and not re.search(r"未签到|未能签到|没有签到|未登录|请.*登录", message)
            and any(text in message for text in ("已经签到", "已签到", "您今天已于")))


def load_env_file():
    """
    加载脚本所在目录的 .env 文件，支持两种格式：
    1. 标准键值对：KEY=VALUE
    2. 无键账号行：直接写 邮箱:密码（自动归入 ABLESCI_ACCOUNTS）
    
    优先级：系统环境变量 > .env 中的标准键值对 > .env 中的无键账号行
    重复键会合并（用换行符连接）
    """
    script_dir = Path(__file__).parent
    env_file = script_dir / ".env"
    if not env_file.exists():
        return

    env_vars = {}
    account_lines = []

    with open(env_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # 无键账号行的密码也可能包含等号，不能将其当作环境变量名输出。
            if '=' in line and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', line.split('=', 1)[0].strip()):
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                if key in env_vars:
                    env_vars[key] = env_vars[key] + "\n" + value
                else:
                    env_vars[key] = value
            else:
                account_lines.append(line)

    for key, value in env_vars.items():
        if key not in os.environ:
            os.environ[key] = value
            print(f"已从 {env_file} 设置环境变量: {key}")
        else:
            print(f"环境变量 {key} 已存在（来自系统），跳过 .env 中的值")

    if ENV_ACCOUNTS not in os.environ and ENV_ACCOUNTS not in env_vars:
        if account_lines:
            accounts_value = "\n".join(account_lines)
            os.environ[ENV_ACCOUNTS] = accounts_value
            print(f"已从 {env_file} 的无键行设置 {ENV_ACCOUNTS}（共 {len(account_lines)} 个账号）")
    elif account_lines:
        print(f"警告：存在无键账号行，但 {ENV_ACCOUNTS} 已通过系统或标准键值对设置，忽略无键行")

    if ENV_ACCOUNTS in os.environ:
        val = os.environ[ENV_ACCOUNTS]
        # 隐私保护：只保留邮箱前缀，密码一律隐去
        safe_lines = []
        for line in val.splitlines():
            if ":" in line:
                local = line.split(":", 1)[0].strip()
                safe_lines.append((local[:2] + "***") if local else "***")
            else:
                safe_lines.append("***")
        safe = " / ".join(safe_lines)
        print(f"当前 {ENV_ACCOUNTS} 内容预览: {safe}（共 {len(safe_lines)} 个账号，密码已隐藏）")


def get_beijing_time():
    """
    返回北京时间（带时区信息）
    优先使用 zoneinfo，如果失败则尝试 pytz，最后使用手动 UTC+8 偏移。
    """
    if ZONEINFO_AVAILABLE:
        try:
            return datetime.datetime.now(ZoneInfo("Asia/Shanghai"))
        except Exception:
            pass
        
    try:
        import pytz
        return datetime.datetime.now(pytz.timezone("Asia/Shanghai"))
    except ImportError:
        pass

    return datetime.datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=8)))


def protect_privacy(text):
    """保护隐私信息，隐藏部分邮箱和用户名"""
    if not text:
        return text
        
    # 邮箱隐私处理
    if "@" in text:
        parts = text.split("@")
        
        # 1. 处理 @ 前面的部分（保持原有逻辑）
        if len(parts[0]) > 2:
            protected_local = parts[0][:2] + "***"
        else:
            protected_local = "***"
            
        # 2. 处理 @ 后面的部分（修改处）
        # 获取域名部分
        domain = parts[1]
        
        # 方式A：完全隐藏域名 (输出示例: te***@***)
        # protected_domain = "***"
        
        # 方式B：隐藏域名主体，保留后缀 (输出示例: te***@***.com) - 推荐，看起来更像邮箱
        if "." in domain:
            try:
                # 分割域名和后缀
                domain_parts = domain.split(".", 1)
                protected_domain = "***." + domain_parts[1]
            except:
                protected_domain = "***"
        else:
            protected_domain = "***"
            
        return f"{protected_local}@{protected_domain}"
    
    # 用户名隐私处理（保持原有逻辑）
    if len(text) > 2:
        return text[:2] + "***"
    else:
        return "***"


class Notifier:
    def __init__(self, title="科研通签到"):
        self.log_content = []
        self.title = title
        self.notify_enabled = False
        
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from sendNotify import send
            self.send = send
            self.notify_enabled = True
        except ImportError:
            try:
                parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                sys.path.append(parent_dir)
                from sendNotify import send
                self.send = send
                self.notify_enabled = True
            except Exception as e:
                self.log(f"导入通知模块失败: {str(e)}", "warning")
                self.notify_enabled = False
    
    def log(self, message, level="info"):
        """格式化日志输出并保存到内容 - 使用北京时间"""
        beijing_time = get_beijing_time()
        timestamp = beijing_time.strftime("%Y-%m-%d %H:%M:%S")
        
        level_map = {
            "info": "ℹ️",
            "success": "✅",
            "error": "❌",
            "warning": "⚠️"
        }
        symbol = level_map.get(level, "ℹ️")
        log_message = f"[{timestamp}] {symbol} {message}"
        print(log_message)
        self.log_content.append(log_message)
        
    def send_notification(self, content=None):
        """发送通知"""
        if not self.notify_enabled:
            self.log("通知功能未启用", "warning")
            return False
            
        if content is None:
            content = "\n".join(self.log_content)
        
        try:
            self.send(self.title, content)
            self.log("通知发送成功", "success")
            return True
        except Exception as e:
            self.log(f"发送通知失败: {type(e).__name__}", "error")
            return False
    
    def get_content(self):
        """获取日志内容"""
        return "\n".join(self.log_content)


class AbleSciAuto:
    def __init__(self, email, password, notifier=None):
        self.session = requests.Session()
        self.email = email
        self.password = password
        self.username = None
        self.points = None
        self.sign_days = None
        self.failure_reason = "login_failed"
        self.notifier = notifier if notifier else Notifier()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "X-Requested-With": "XMLHttpRequest"
        }
        self.start_time = time.time()
        protected_email = protect_privacy(self.email)
        self.log(f"处理账号: {protected_email}", "info")
        
    def log(self, message, level="info"):
        """服务端消息也需脱敏，异常正文和请求凭据不进入日志。"""
        message = str(message)
        if self.password:
            message = message.replace(self.password, "***")
        message = EMAIL_RE.sub(lambda m: protect_privacy(m.group()), message)
        self.notifier.log(message, level)

    def fail(self, reason, detail=""):
        self.failure_reason = reason
        self.log(FAILURE_LABELS[reason] + (f"：{detail}" if detail else ""), "error")
        return False

    def result(self, status, reason=""):
        return AccountResult(protect_privacy(self.email), status, reason)
        
    def get_csrf_token(self):
        """获取CSRF令牌

        2026-09-15 站点前端改版：登录页不再输出 <input name="_csrf">，
        令牌改为 <meta name="csrf-token" content="...">（同名 input 由 JS 在提交前填充，
        静态抓取拿不到），同时新增 iframe 图形验证码（仅风控命中时触发）与
        /site/confirm-login 二次确认（实测签到不需要走这一步）。
        保留 input[_csrf] 作为回退，防止站点再改回去。
        """
        login_url = "https://www.ablesci.com/site/login"
        try:
            response = self.session.get(login_url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                token = ''
                meta = soup.find('meta', {'name': 'csrf-token'})
                if meta and meta.get('content'):
                    token = meta.get('content', '').strip()
                if not token:
                    csrf_input = soup.find('input', {'name': '_csrf'})
                    if csrf_input:
                        token = csrf_input.get('value', '').strip()
                if token:
                    return token
                self.fail("csrf_missing")
            else:
                reason = "rate_limited" if response.status_code == 429 else "http_error"
                self.fail(reason, f"获取登录页 HTTP {response.status_code}")
        except requests.Timeout:
            self.fail("timeout", "获取登录页")
        except requests.RequestException:
            self.fail("network_error", "获取登录页")
        return ''

    def login(self):
        """执行登录操作"""
        if not self.email or not self.password:
            return self.fail("login_failed", "邮箱或密码为空")
            
        login_url = "https://www.ablesci.com/site/login"
        csrf_token = self.get_csrf_token()
        
        if not csrf_token:
            return False
        
        login_data = {
            "_csrf": csrf_token,
            "email": self.email,
            "password": self.password,
            "remember": "off"
        }
        
        headers = self.headers.copy()
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        headers["Referer"] = "https://www.ablesci.com/site/login"
        
        try:
            response = self.session.post(
                login_url,
                data=login_data,
                headers=headers,
                timeout=30
            )
            
            try:
                result = response.json()
            except ValueError:
                result = None
            reason = response_failure(result, response.status_code)
            if reason:
                return self.fail(reason)
            if response.status_code != 200:
                return self.fail("http_error", f"登录 HTTP {response.status_code}")
            if not isinstance(result, dict):
                # 兼容旧站点的已登录 HTML，不能仅凭页面中出现“退出”字样判成功。
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.select_one('a[href^="/site/logout"]'):
                    self.log("登录成功", "success")
                    return True
                return self.fail("invalid_response", "登录接口未返回 JSON")
            if type(result.get("code")) is int and result["code"] == 0:
                self.log("登录成功", "success")
                return True
            return self.fail("login_failed", str(result.get("msg") or "账号验证未通过"))
        except requests.Timeout:
            return self.fail("timeout", "登录请求")
        except requests.RequestException:
            return self.fail("network_error", "登录请求")

    def get_user_info(self):
        """获取用户信息（包括用户名、积分和签到天数）"""
        home_url = "https://www.ablesci.com/"
        headers = self.headers.copy()
        headers["Referer"] = "https://www.ablesci.com/"
        
        try:
            response = self.session.get(home_url, headers=headers, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 用户名
                username_element = soup.select_one('.mobile-hide.able-head-user-vip-username')
                if username_element:
                    self.username = username_element.text.strip()
                    protected_username = protect_privacy(self.username)
                    self.log(f"用户名: {protected_username}", "info")
                else:
                    self.log("无法定位用户名元素", "warning")
                
                # 积分
                points_element = soup.select_one('#user-point-now')
                if points_element:
                    self.points = points_element.text.strip()
                    self.log(f"当前积分: {self.points}", "info")
                else:
                    self.log("无法获取积分信息", "warning")
                
                # 连续签到天数
                sign_days_element = soup.select_one('#sign-count')
                if sign_days_element:
                    self.sign_days = sign_days_element.text.strip()
                    self.log(f"连续签到天数: {self.sign_days}", "info")
                else:
                    self.log("无法获取连续签到天数", "warning")
                
                return True
            else:
                self.log(f"获取用户信息失败，HTTP {response.status_code}", "warning")
        except Exception as e:
            self.log(f"获取用户信息时出错: {type(e).__name__}", "warning")
        return False

    def sign_in(self):
        """执行签到操作 - 处理已签到情况"""
        sign_url = "https://www.ablesci.com/user/sign"
        headers = self.headers.copy()
        headers["Referer"] = "https://www.ablesci.com/"
        
        try:
            response = self.session.get(sign_url, headers=headers, timeout=30)
            try:
                result = response.json()
            except ValueError:
                result = None
            reason = response_failure(result, response.status_code)
            if reason:
                self.fail(reason)
            elif response.status_code != 200:
                self.fail("http_error", f"签到 HTTP {response.status_code}")
            elif not isinstance(result, dict):
                self.fail("invalid_response", "签到接口未返回 JSON 对象")
            elif type(result.get("code")) is not int:
                self.fail("invalid_response", "签到响应缺少有效状态码")
            elif already_signed(result.get("msg", "")):
                self.log(f"今日已签到: {result.get('msg')}", "success")
                return self.result("already_signed")
            elif result["code"] == 0:
                self.log(f"签到成功: {result.get('msg')}", "success")
                data = result.get("data", {})
                if isinstance(data, dict):
                    self.points = data.get("points", self.points)
                    self.sign_days = data.get("sign_days", self.sign_days)
                return self.result("signed")
            else:
                self.fail("sign_failed", str(result.get("msg") or "服务端未确认签到"))
        except requests.Timeout:
            self.fail("timeout", "签到请求")
        except requests.RequestException:
            self.fail("network_error", "签到请求")
        return self.result("failed", self.failure_reason)

    def display_summary(self, is_before_sign=False):
        """显示执行摘要"""
        elapsed = round(time.time() - self.start_time, 2)
        title = "签到前信息" if is_before_sign else "签到后信息"
        self.log("=" * 50)
        self.log(f"用户 {protect_privacy(self.username)} {title}:")
        if self.username:
            self.log(f"  • 用户名: {protect_privacy(self.username)}")
        if self.points:
            self.log(f"  • 当前积分: {self.points}")
        if self.sign_days:
            self.log(f"  • 连续签到: {self.sign_days}天")
        self.log(f"  • 执行耗时: {elapsed}秒")
        self.log("=" * 50)
        self.log("")

    def run(self):
        """只以签到接口响应确定结果，展示信息失败不覆盖已确认的结果。"""
        try:
            if not self.login():
                return self.result("failed", self.failure_reason)
            self.show_user_info(is_before_sign=True)
            result = self.sign_in()
            if result.ok:
                time.sleep(2)
                self.show_user_info()
            return result
        except Exception as e:
            self.fail("unexpected_error", type(e).__name__)
            return self.result("failed", self.failure_reason)
        finally:
            try:
                self.session.close()
            except Exception as e:
                self.log(f"关闭账号会话失败: {type(e).__name__}", "warning")

    def show_user_info(self, is_before_sign=False):
        try:
            if self.get_user_info():
                self.display_summary(is_before_sign=is_before_sign)
        except Exception as e:
            self.log(f"用户信息展示失败: {type(e).__name__}", "warning")


def get_accounts():
    """从环境变量获取所有账号

    支持旧格式：
    - 换行分隔多个账号
    - 同一行用逗号或分号分隔多个账号
    - 单个账号使用 邮箱:密码 或 邮箱|密码

    解析时以“邮箱”为锚点，避免密码中的逗号/分号被误拆。
    """
    accounts_env = os.getenv(ENV_ACCOUNTS)
    if not accounts_env:
        return []

    valid_accounts = []

    for line_no, raw_line in enumerate(accounts_env.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue

        matches = list(EMAIL_RE.finditer(line))
        if not matches:
            # 隐私保护：不打印任何原始内容
            print(f"警告：第 {line_no} 行未找到邮箱格式账号（内容已隐藏）")
            continue

        for i, m in enumerate(matches):
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(line)

            segment = line[start:end].rstrip()

            # 若后面还有下一个邮箱，说明末尾的 , 或 ; 是账号分隔符，去掉一个
            if i + 1 < len(matches) and segment.endswith((',', ';')):
                segment = segment[:-1].rstrip()

            email = m.group(0)
            rest = segment[len(email):]

            if rest.startswith(':') or rest.startswith('|'):
                password = rest[1:].strip()
            else:
                # 隐私保护：不打印任何原始内容
                print(f"警告：第 {line_no} 行账号格式错误（内容已隐藏）")
                continue

            if password:
                valid_accounts.append((email, password))
            else:
                print(f"警告：第 {line_no} 行密码为空（内容已隐藏）")

    return valid_accounts


def main():
    """主函数，处理多账号签到，统一通知器"""
    load_env_file()
    # 创建全局通知器，所有账号共享
    global_notifier = Notifier("科研通多账号签到")
    global_notifier.log("科研通多账号签到任务开始", "info")
    
    accounts = get_accounts()
    account_count = len(accounts)
    
    if account_count == 0:
        global_notifier.log("未找到有效的账号配置", "error")
        global_notifier.log(f"请设置环境变量 {ENV_ACCOUNTS}，格式为：邮箱1:密码1[换行]邮箱2:密码2", "warning")
        if global_notifier.notify_enabled:
            global_notifier.send_notification()
        return 1
    
    global_notifier.log(f"找到 {account_count} 个账号", "info")
    
    results = []
    for i, (email, password) in enumerate(accounts, 1):
        global_notifier.log(f"\n===== 开始处理第 {i}/{account_count} 个账号 =====", "info")
        
        try:
            automator = AbleSciAuto(email, password, notifier=global_notifier)
            result = automator.run()
        except Exception as e:
            global_notifier.log(f"账号处理异常: {type(e).__name__}", "error")
            result = AccountResult(protect_privacy(email), "failed", "unexpected_error")
        results.append(result)
        
        global_notifier.log(f"===== 完成第 {i}/{account_count} 个账号处理 =====", "info")
    
    global_notifier.log("\n===== 所有账号处理完成 =====", "info")

    labels = {"signed": "签到成功", "already_signed": "今日已签到", "failed": "失败"}
    summary = []
    for i, result in enumerate(results, 1):
        line = f"账号 {i} {result.account}：{labels[result.status]}"
        if result.reason:
            line += f"（{FAILURE_LABELS[result.reason]}；{result.reason}）"
        summary.append(line)
    failed_count = sum(not result.ok for result in results)
    summary.append(f"汇总：{len(results)} 个账号，{len(results) - failed_count} 个成功或已签到，{failed_count} 个失败")
    summary_content = "\n".join(summary)
    global_notifier.log(summary_content, "error" if failed_count else "success")
    
    if global_notifier.notify_enabled:
        global_notifier.send_notification(content=summary_content)

    # 已移除 set-output（GitHub 早已弃用，且会把日志再输出一次）。
    # 若需要在 workflow 中使用日志，请改用 $GITHUB_OUTPUT 或写入文件。
    return 1 if failed_count else 0


if __name__ == "__main__":
    sys.exit(main())
