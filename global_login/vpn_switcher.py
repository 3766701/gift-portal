import requests
import time
import logging
import os
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Optional


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class VPNSwitcher:
    """VPN切换器类，用于自动切换VPN节点以避免请求频率限制"""
    DEFAULT_PROXY_GROUP = "🔰国外流量"
    
    def __init__(self, proxy_group: Optional[str] = None):
        self.vpn_switch_lock = threading.Lock()  # VPN切换锁
        self.node_locked = False  # 节点锁定开关，开启后禁止切换
        # 创建Session对象用于复用TCP连接
        self.session = requests.Session()
        # 配置Session的连接池参数
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,  # 连接池大小
            pool_maxsize=20,      # 最大连接数
            max_retries=2,        # 重试次数
            pool_block=False      # 非阻塞模式
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.vpn_switching = threading.Event()  # VPN切换事件标志
        self.status_callbacks = []  # VPN状态变化回调函数列表
        
        # VPN相关配置（硬编码）（硬编码）
        self.proxy_group = self._normalize_proxy_group(proxy_group)  # 可由GUI输入覆盖
        # Use the Steam auth endpoint as the latency target. Mihomo's delay
        # probe only tests reachability/latency and does not submit credentials.
        self.test_url = "https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1/"
        self.max_latency = 3000  # 最大允许延迟(毫秒)
        self.test_timeout = 5  # 节点测试超时时间(秒)
        self.max_retries = 3  # 请求重试次数
        self.switch_wait_time = 3  # VPN切换后等待时间(秒)
        
        # 代理配置
        self.proxy_host = "127.0.0.1"
        self.proxy_port = 7890  # Clash默认HTTP代理端口
        self.proxies = {
            'http': f'http://{self.proxy_host}:{self.proxy_port}',
            'https': f'http://{self.proxy_host}:{self.proxy_port}'
        }
        
        # 加载Clash配置
        self._load_clash_config()
        
        self.available_nodes = []  # 存储可用节点
        self.current_node_index = 0  # 当前节点索引

        # \u8282\u70b9\u4f7f\u7528\u8bb0\u5f55\uff1a30\u5206\u949f\u5185\u7528\u8fc7\u7684\u8282\u70b9\u6682\u65f6\u8df3\u8fc7\u3002
        self.node_usage_ttl_sec = 30 * 60
        self.node_usage_file = os.path.join(
            os.environ.get('LOCALAPPDATA') or os.path.dirname(os.path.abspath(__file__)),
            'DDCDK',
            'clash_node_usage.json'
        )
        self.node_usage = self._load_node_usage()
        
        # 初始化时获取可用节点
        self._init_available_nodes()

    @classmethod
    def _normalize_proxy_group(cls, proxy_group: Optional[str]) -> str:
        """规范化代理组名称，空值时回退到默认值"""
        if proxy_group is None:
            return cls.DEFAULT_PROXY_GROUP

        normalized = str(proxy_group).strip()
        return normalized or cls.DEFAULT_PROXY_GROUP
    

    
    def _load_clash_config(self):
        """从系统目录加载Clash配置"""
        try:
            # 获取Clash配置文件路径
            config_paths = [
                # # Clash Verge Rev 常见路径
                # os.path.join(os.environ.get('APPDATA', ''), 'io.github.clash-verge-rev.clash-verge-rev', 'config.yaml'),
                # os.path.join(os.environ.get('APPDATA', ''), 'io.github.clash-verge-rev.clash-verge-rev', 'verge.yaml'),
                # os.path.join(os.environ.get('APPDATA', ''), 'io.github.clash-verge-rev.clash-verge-rev', 'clash-verge.yaml'),
                # Windows常见路径
                os.path.join(os.environ.get('USERPROFILE', ''), '.config', 'clash', 'config.yaml'),
                os.path.join(os.environ.get('APPDATA', ''), 'clash', 'config.yaml'),
                # Mihomo on Linux (including root deployments)
                os.path.join(os.environ.get('XDG_CONFIG_HOME', ''), 'mihomo', 'config.yaml'),
                os.path.expanduser('~/.config/mihomo/config.yaml'),
                os.path.expanduser('~/.config/clash/config.yaml'),
                # 当前目录
                'config.yaml',
                'clash_config.yaml'
            ]
            
            config_found = False
            for config_path in config_paths:
                if os.path.exists(config_path):
                    logging.info(f"找到Clash配置文件: {config_path}")
                    try:
                        # 简单的文本解析，避免yaml依赖
                        with open(config_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # 解析external-controller
                        for line in content.split('\n'):
                            line = line.strip()
                            if line.startswith('external-controller:'):
                                controller = line.split(':', 1)[1].strip().strip('"\'')
                                if not controller.startswith('http'):
                                    controller = f"http://{controller}"
                                self.clash_api = controller
                                config_found = True
                                break
                        
                        # 解析secret
                        for line in content.split('\n'):
                            line = line.strip()
                            if line.startswith('secret:'):
                                secret = line.split(':', 1)[1].strip().strip('"\'')
                                self.clash_secret = secret
                                break
                        else:
                            self.clash_secret = ""
                        
                        # 解析 HTTP 代理端口；Mihomo commonly uses mixed-port.
                        port_keys = ('mixed-port:', 'port:', 'http-port:')
                        for line in content.split('\n'):
                            line = line.strip()
                            port_key = next((key for key in port_keys if line.startswith(key)), None)
                            if port_key:
                                try:
                                    port = int(line.split(':', 1)[1].strip())
                                    self.proxy_port = port
                                    # 更新代理配置
                                    self.proxies = {
                                        'http': f'http://{self.proxy_host}:{self.proxy_port}',
                                        'https': f'http://{self.proxy_host}:{self.proxy_port}'
                                    }
                                    logging.info(f"从配置文件读取到HTTP代理端口: {self.proxy_port}")
                                except ValueError:
                                    logging.warning("配置文件中的port值无效，使用默认端口7890")
                                break
                        
                        if config_found:
                            logging.info(f"从配置文件加载Clash API: {self.clash_api}")
                            break
                            
                    except Exception as e:
                        logging.warning(f"读取配置文件 {config_path} 失败: {str(e)}")
                        continue
            
            if not config_found:
                # 使用默认配置
                self.clash_api = "http://127.0.0.1:9090"
                self.clash_secret = ""
                logging.warning("未找到有效的Clash配置文件，使用默认配置")
            
        except Exception as e:
            logging.error(f"加载Clash配置失败: {str(e)}，使用默认配置")
            self.clash_api = "http://127.0.0.1:9090"
            self.clash_secret = ""
        
        logging.info(f"Clash API配置: {self.clash_api}")
        logging.info(f"代理配置: {self.proxies}")
        logging.info(f"VPN配置: 代理组={self.proxy_group}, 最大延迟={self.max_latency}ms")
    
    def _init_available_nodes(self):
        """初始化并测试所有可用的VPN线路"""
        try:
            logging.info("正在获取并测试所有VPN线路...")
            all_nodes = self._get_all_nodes()
            if not all_nodes:
                logging.warning("未能获取到VPN线路列表")
                return
            
            # 使用多线程测试线路延迟
            logging.info(f"准备测试 {len(all_nodes)} 个线路...")
            available_nodes = self._test_nodes_with_threadpool(all_nodes)
            
            # 按延迟排序，只保留前20个低延迟节点
            available_nodes.sort(key=lambda x: x[1])
            top_20_nodes = available_nodes[:20]  # 只取前20个低延迟节点
            self.available_nodes = [node for node, _ in top_20_nodes]
            
            if self.available_nodes:
                logging.info(f"找到 {len(self.available_nodes)} 个可用VPN线路")
                # 切换到延迟最低的线路
                self._switch_to_next_node(force_first=True)
            else:
                logging.warning("没有找到可用的VPN线路")
                
        except Exception as e:
            logging.error(f"初始化VPN线路时出错: {str(e)}")
    
    def _test_nodes_with_threadpool(self, nodes: List[str], max_workers: int = 30) -> List[Tuple[str, int]]:
        """多线程测试线路延迟"""
        from concurrent.futures import as_completed
        
        results = []
        completed_count = 0
        total_count = len(nodes)
        
        logging.info(f"开始测试 {total_count} 个VPN线路，使用 {max_workers} 个线程...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 创建测试任务
            future_to_node = {
                executor.submit(self._test_node_latency, node): node 
                for node in nodes
            }
            
            # 使用as_completed获得实时反馈
            for future in as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    latency = future.result()
                    completed_count += 1
                    
                    if latency and latency <= self.max_latency:
                        results.append((node, latency))
                        logging.info(f"✓ {node}: {latency}ms ({completed_count}/{total_count})")
                    else:
                        logging.debug(f"✗ {node}: {latency}ms 延迟过高 ({completed_count}/{total_count})")
                except Exception as e:
                    completed_count += 1
                    logging.error(f"✗ {node}: 测试失败 - {str(e)} ({completed_count}/{total_count})")
        
        # 按延迟排序
        results.sort(key=lambda x: x[1])
        logging.info(f"线路测试完成！共测试 {total_count} 个线路，可用线路 {len(results)} 个")
        if results:
            logging.info(f"最佳线路: {results[0][0]} ({results[0][1]}ms)")
        
        return results
    
    def _get_all_nodes(self) -> List[str]:
        """获取所有VPN线路（所有协议的节点）"""
        try:
            headers = {"Authorization": f"Bearer {self.clash_secret}"} if self.clash_secret else {}

            response = self.session.get(f"{self.clash_api}/proxies", headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # 检查代理组是否存在
            if self.proxy_group not in data["proxies"]:
                # Fall back to the first selector/url-test group exposed by Mihomo.
                candidates = [
                    (name, value) for name, value in data["proxies"].items()
                    if isinstance(value, dict) and value.get("all")
                ]
                if not candidates:
                    logging.error(f"代理组 '{self.proxy_group}' 不存在且未发现可用代理组")
                    return []
                self.proxy_group, _ = candidates[0]
                logging.warning(f"默认代理组不存在，自动使用代理组 '{self.proxy_group}'")
            
            all_nodes = data["proxies"][self.proxy_group]["all"]
            supported_nodes = []
            node_stats = {}
            region_stats = {}
            
            # 收集所有协议的节点（排除DIRECT、REJECT等特殊节点）
            excluded_types = ["direct", "reject", "selector", "urltest", "fallback", "loadbalance"]
            
            for node in all_nodes:
                if node in data["proxies"]:
                    node_info = data["proxies"][node]
                    node_type = node_info.get("type", "").lower()
                    
                    # 排除特殊类型的节点，只保留真正的代理节点
                    if node_type not in excluded_types and node_type:
                        supported_nodes.append(node)
                        
                        # 统计各协议类型数量
                        if node_type not in node_stats:
                            node_stats[node_type] = 0
                        node_stats[node_type] += 1
                        
                        # 统计地区分布（简单识别常见地区关键词）
                        region = "其他"
                        if "香港" in node or "HK" in node.upper():
                            region = "香港"
                        elif "台湾" in node or "TW" in node.upper():
                            region = "台湾"
                        elif "新加坡" in node or "SG" in node.upper():
                            region = "新加坡"
                        elif "日本" in node or "JP" in node.upper():
                            region = "日本"
                        elif "美国" in node or "US" in node.upper():
                            region = "美国"
                        elif "韩国" in node or "KR" in node.upper():
                            region = "韩国"
                        elif "英国" in node or "UK" in node.upper():
                            region = "英国"
                        elif "德国" in node or "DE" in node.upper():
                            region = "德国"
                        elif "法国" in node or "FR" in node.upper():
                            region = "法国"
                        elif "加拿大" in node or "CA" in node.upper():
                            region = "加拿大"
                        elif "澳大利亚" in node or "AU" in node.upper():
                            region = "澳大利亚"
                        
                        if region not in region_stats:
                            region_stats[region] = 0
                        region_stats[region] += 1
            
            # 输出详细的节点统计信息
            protocol_info = ", ".join([f"{protocol}: {count}" for protocol, count in node_stats.items()])
            region_info = ", ".join([f"{region}: {count}" for region, count in region_stats.items()])
            logging.info(f"从 {len(all_nodes)} 个线路中筛选出 {len(supported_nodes)} 个节点（所有协议）")
            logging.info(f"协议分布: {protocol_info}")
            logging.info(f"地区分布: {region_info}")
            
            return supported_nodes
        except Exception as e:
            logging.error(f"获取VPN线路列表失败: {str(e)}")
            return []
    
    def _test_node_latency(self, node: str) -> int:
        """测试线路延迟"""
        try:
            headers = {"Authorization": f"Bearer {self.clash_secret}"} if self.clash_secret else {}
            params = {
                "url": self.test_url,
                "timeout": min(self.test_timeout * 1000, 5000)  # 限制最大5秒超时
            }

            response = self.session.get(
                f"{self.clash_api}/proxies/{node}/delay",
                headers=headers,
                params=params,
                timeout=6  # 减少请求超时时间
            )
            data = response.json()
            return data.get("delay", 9999)
        except Exception as e:
            logging.debug(f"测试线路 {node} 延迟失败: {str(e)}")
            return 9999

    def refresh_nodes(self) -> None:
        """Re-fetch, measure, sort, and select the best available nodes."""
        self.available_nodes = []
        self.current_node_index = 0
        self._init_available_nodes()
    
    def _node_usage_key(self, node: str) -> str:
        return f"{self.proxy_group}|{node}"

    def _load_node_usage(self) -> dict:
        try:
            if not os.path.exists(self.node_usage_file):
                return {}
            with open(self.node_usage_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return {}
            now = time.time()
            return {str(k): float(v) for k, v in data.items() if isinstance(v, (int, float)) and now - float(v) < self.node_usage_ttl_sec}
        except Exception as e:
            logging.warning(f"\u52a0\u8f7d Clash \u8282\u70b9\u4f7f\u7528\u8bb0\u5f55\u5931\u8d25: {e}")
            return {}

    def _save_node_usage(self):
        try:
            os.makedirs(os.path.dirname(self.node_usage_file), exist_ok=True)
            with open(self.node_usage_file, 'w', encoding='utf-8') as f:
                json.dump(self.node_usage, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logging.warning(f"\u4fdd\u5b58 Clash \u8282\u70b9\u4f7f\u7528\u8bb0\u5f55\u5931\u8d25: {e}")

    def _prune_node_usage(self):
        now = time.time()
        before = len(self.node_usage)
        self.node_usage = {k: float(v) for k, v in self.node_usage.items() if now - float(v) < self.node_usage_ttl_sec}
        if len(self.node_usage) != before:
            self._save_node_usage()

    def _is_node_recently_used(self, node: str) -> bool:
        self._prune_node_usage()
        used_at = self.node_usage.get(self._node_usage_key(node))
        return used_at is not None and time.time() - float(used_at) < self.node_usage_ttl_sec

    def _mark_node_used(self, node: str):
        self._prune_node_usage()
        self.node_usage[self._node_usage_key(node)] = time.time()
        self._save_node_usage()
        logging.info(f"\u5df2\u8bb0\u5f55 Clash \u8282\u70b9\u4f7f\u7528\uff1a{node}\uff0c30\u5206\u949f\u5185\u8df3\u8fc7")

    def _select_next_eligible_node_index(self, force_first: bool = False) -> Optional[int]:
        if not self.available_nodes:
            return None
        count = len(self.available_nodes)
        order = list(range(count)) if force_first else [((self.current_node_index + step) % count) for step in range(1, count + 1)]
        skipped = []
        for idx in order:
            node = self.available_nodes[idx]
            if self._is_node_recently_used(node):
                skipped.append(node)
                continue
            if skipped:
                preview = ', '.join(skipped[:5]) + ('...' if len(skipped) > 5 else '')
                logging.info(f"\u5df2\u8df3\u8fc7 {len(skipped)} \u4e2a30\u5206\u949f\u5185\u4f7f\u7528\u8fc7\u7684 Clash \u8282\u70b9: {preview}")
            return idx
        logging.warning("\u6240\u6709\u53ef\u7528 Clash \u8282\u70b9\u90fd\u572830\u5206\u949f\u5185\u4f7f\u7528\u8fc7\uff0c\u6682\u65e0\u53ef\u5207\u6362\u8282\u70b9")
        return None

    def _switch_to_next_node(self, force_first: bool = False, bypass_lock: bool = False) -> bool:
        """切换到下一个可用线路"""
        with self.vpn_switch_lock:
            if self.node_locked and not bypass_lock:
                logging.info("VPN节点已锁定，跳过线路切换请求")
                return False

            if not self.available_nodes:
                logging.warning("没有可用的VPN线路可供切换")
                return False
                
            # 设置VPN切换标志
            self.vpn_switching.set()
            
            try:
                next_index = self._select_next_eligible_node_index(force_first=force_first)
                if next_index is None:
                    return False

                self.current_node_index = next_index
                next_node = self.available_nodes[self.current_node_index]
                
                headers = {"Authorization": f"Bearer {self.clash_secret}"} if self.clash_secret else {}
                headers["Content-Type"] = "application/json"
                data = {"name": next_node}
                response = self.session.put(
                    f"{self.clash_api}/proxies/{self.proxy_group}",
                    headers=headers,
                    json=data,
                    timeout=10
                )
                
                if response.status_code == 204:
                    logging.info(f"成功切换到VPN线路: {next_node}")
                    self._mark_node_used(next_node)
                    # 切换线路后等待一段时间让连接稳定
                    time.sleep(self.switch_wait_time)
                    # 通知状态变化
                    self._notify_status_change()
                    return True
                else:
                    logging.error(f"切换VPN线路失败: {response.status_code}")
                    return False
            except Exception as e:
                logging.error(f"切换VPN线路时出错: {str(e)}")
                return False
            finally:
                # 清除VPN切换标志
                self.vpn_switching.clear()
    
    def _wait_for_vpn_ready(self, timeout: int = 30) -> bool:
        """等待VPN切换完成"""
        start_time = time.time()
        while self.vpn_switching.is_set():
            if time.time() - start_time > timeout:
                logging.warning("等待VPN切换超时")
                return False
            time.sleep(0.5)
        return True
    
    def handle_rate_limit(self) -> bool:
        """处理请求频率限制，优先选择延迟最低的节点"""
        if self.is_node_locked():
            logging.info("VPN节点已锁定，跳过自动切换")
            return False

        if not self.available_nodes:
            logging.warning("没有可用的VPN线路，无法处理频率限制")
            return False
            
        logging.info("检测到请求频率限制，尝试切换到延迟最低的VPN线路...")
        
        # 如果其他线程正在切换VPN，等待其完成
        if self.vpn_switching.is_set():
            logging.info("其他线程正在切换VPN，等待切换完成...")
            if not self._wait_for_vpn_ready():
                return False
        
        # 优先切换到延迟最低的节点
        if self.switch_to_best_node():
            logging.info("VPN线路切换成功，已切换到延迟最低的线路")
            return True
        else:
            logging.error("VPN线路切换失败")
            return False
    
    def make_request(self, method: str, url: str, max_retries: int = None, **kwargs) -> Optional[requests.Response]:
        """统一的请求处理方法，自动处理VPN切换"""
        if max_retries is None:
            max_retries = self.max_retries
        retry_count = 0
        
        # 确保使用代理配置
        if 'proxies' not in kwargs:
            kwargs['proxies'] = self.proxies
        
        # 设置默认超时时间
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 30
        
        # 禁用SSL验证以避免代理SSL问题
        if 'verify' not in kwargs:
            kwargs['verify'] = False
        
        # 禁用SSL警告
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        while retry_count < max_retries:
            # 如果VPN正在切换，等待切换完成
            if self.vpn_switching.is_set():
                logging.info("VPN正在切换中，等待切换完成...")
                if not self._wait_for_vpn_ready():
                    return None
            
            try:
                response = self.session.request(method, url, **kwargs)
                
                # 处理403错误（频率限制）
                if response.status_code == 403:
                    logging.warning(f"收到403状态码，可能遇到频率限制")
                    if not self.handle_rate_limit():
                        retry_count += 1
                        continue
                    # VPN切换成功后重试
                    continue
                
                # 处理429错误（Too Many Requests）
                if response.status_code == 429:
                    logging.warning(f"收到429状态码，请求过于频繁")
                    if not self.handle_rate_limit():
                        retry_count += 1
                        continue
                    # VPN切换成功后重试
                    continue
                
                return response
                
            except requests.exceptions.RequestException as e:
                logging.error(f"请求出错: {str(e)}")
                
                # 检查是否为需要切换VPN的网络错误
                should_switch_vpn = False
                
                # SSL连接错误
                if "SSL" in str(e) or "EOF occurred" in str(e):
                    logging.warning("检测到SSL连接错误，尝试切换VPN线路...")
                    should_switch_vpn = True
                
                # HTTP连接失败错误
                elif isinstance(e, (requests.exceptions.ConnectionError, 
                                   requests.exceptions.ConnectTimeout,
                                   requests.exceptions.ReadTimeout)):
                    logging.warning(f"检测到网络连接错误: {type(e).__name__}，尝试切换VPN线路...")
                    should_switch_vpn = True
                
                # 代理连接错误
                elif "ProxyError" in str(e) or "proxy" in str(e).lower():
                    logging.warning("检测到代理连接错误，尝试切换VPN线路...")
                    should_switch_vpn = True
                
                # 如果需要切换VPN，尝试切换
                if should_switch_vpn:
                    if self.handle_rate_limit():
                        continue
                
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(1)
                    continue
                return None
        
        return None
    
    def get_current_node(self) -> Optional[str]:
        """获取当前使用的VPN线路"""
        if self.available_nodes and 0 <= self.current_node_index < len(self.available_nodes):
            return self.available_nodes[self.current_node_index]
        return None
    
    def get_available_nodes_count(self) -> int:
        """获取可用线路数量"""
        return len(self.available_nodes)
    
    def is_vpn_available(self) -> bool:
        """检查VPN是否可用"""
        return len(self.available_nodes) > 0

    def get_proxy_group(self) -> str:
        """获取当前代理组名称"""
        return self.proxy_group

    def set_proxy_group(self, proxy_group: Optional[str]) -> bool:
        """更新代理组并重新初始化可用线路"""
        new_proxy_group = self._normalize_proxy_group(proxy_group)
        if new_proxy_group == self.proxy_group:
            logging.info(f"代理组未变化，继续使用: {self.proxy_group}")
            return True

        old_proxy_group = self.proxy_group
        with self.vpn_switch_lock:
            self.proxy_group = new_proxy_group
            self.available_nodes = []
            self.current_node_index = 0

        logging.info(f"代理组已更新: {old_proxy_group} -> {self.proxy_group}")
        self._init_available_nodes()
        self._notify_status_change()
        return self.is_vpn_available()

    def set_node_lock(self, locked: bool):
        """设置节点锁定状态"""
        lock_changed = False
        with self.vpn_switch_lock:
            new_state = bool(locked)
            if self.node_locked != new_state:
                self.node_locked = new_state
                lock_changed = True

        if lock_changed:
            state_text = "已锁定" if self.node_locked else "已解除"
            logging.info(f"VPN节点锁定状态更新: {state_text}")
            self._notify_status_change()

    def is_node_locked(self) -> bool:
        """是否已锁定当前VPN节点"""
        return self.node_locked
    
    def switch_to_next_node(self) -> bool:
        """切换到下一个VPN线路（公共方法）"""
        return self._switch_to_next_node()
    
    def switch_to_best_node(self) -> bool:
        """切换到延迟最低的VPN线路"""
        return self._switch_to_next_node(force_first=True)
    
    def get_nodes_by_latency(self) -> List[Tuple[str, int]]:
        """获取按延迟排序的节点列表（用于显示）"""
        if not self.available_nodes:
            return []
        
        # 重新测试前20个节点的延迟以获取最新状态
        top_nodes = self.available_nodes[:20]
        current_latencies = []
        
        for node in top_nodes:
            latency = self._test_node_latency(node)
            current_latencies.append((node, latency))
        
        # 按延迟排序
        current_latencies.sort(key=lambda x: x[1])
        return current_latencies
    
    def register_status_callback(self, callback):
        """注册VPN状态变化回调函数"""
        if callback not in self.status_callbacks:
            self.status_callbacks.append(callback)
    
    def unregister_status_callback(self, callback):
        """取消注册VPN状态变化回调函数"""
        if callback in self.status_callbacks:
            self.status_callbacks.remove(callback)
    
    def _notify_status_change(self):
        """通知所有注册的回调函数VPN状态已变化"""
        for callback in self.status_callbacks:
            try:
                callback()
            except Exception as e:
                logging.error(f"调用VPN状态回调函数时出错: {str(e)}")

# 全局VPN切换器实例
vpn_switcher = None

def get_vpn_switcher(proxy_group: Optional[str] = None) -> VPNSwitcher:
    """获取全局VPN切换器实例"""
    global vpn_switcher
    if vpn_switcher is None:
        vpn_switcher = VPNSwitcher(proxy_group=proxy_group)
    elif proxy_group is not None:
        vpn_switcher.set_proxy_group(proxy_group)
    return vpn_switcher

def make_safe_request(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    """安全的请求方法，自动处理VPN切换"""
    switcher = get_vpn_switcher()
    return switcher.make_request(method, url, **kwargs)
