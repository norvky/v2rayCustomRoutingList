"""规则生成器使用的静态常量。"""

from __future__ import annotations

REMARK_TOKEN_MAP = {
    # 将 remarks 中的稳定词元映射为 ASCII 片段，保证 provider/file 名可读且跨平台兼容。
    # 未映射词元会在 to_slug 中被忽略；若不同规则退化到同一 slug，会触发序号后缀并增加引用漂移风险。
    "crack": "crack",
    "bt": "bt",
    "ip": "ip",
    "steam": "steam",
    "域名": "domain",
    "类别": "category",
    "区域": "region",
    "直连": "direct",
    "代理": "proxy",
    "拦截": "block",
    "广告": "ads",
    "端口": "port",
    "全部": "all",
}

POLICY_MAP = {
    # 统一保留三类语义标签，便于后续扩展其它输出模板时复用策略映射。
    "direct": "direct",
    "proxy": "proxy",
    "block": "block",
}

# v2ray protocol 到 Clash 的兼容映射。
# 这里属于“语义近似”而非“语义等价”，因此会在输出里显式标注风险。
PROTOCOL_FALLBACK_MAP = {
    "bittorrent": "GEOSITE,category-pt",
}

# 订阅站模板的可选本地 DNS 补充文件：
# - servers 文件用于声明“客户端可直连访问”的局域网 DNS；生成器会把它们前置到 direct-nameserver。
# - domains 文件用于声明需要强制走本地 DNS 的域名模式；格式直接复用 mihomo nameserver-policy 的 key。
TEMPLATE_LOCAL_DNS_SERVERS_FILE = "template.local-dns-servers.txt"
TEMPLATE_LOCAL_DNS_DOMAINS_FILE = "template.local-dns-domains.txt"
# - disable-ipv6 文件用于声明“保留全局 IPv6、但对少数域名丢弃 AAAA”的策略；
#   适合 Gemini / Google 这类对双栈出口一致性更敏感的站点，格式同样复用 nameserver-policy 的 key。
TEMPLATE_DISABLE_IPV6_DOMAINS_FILE = "template.disable-ipv6-domains.txt"

# redir-host 的默认内网/开发域名基线：
# 1) 这些后缀的共同点是“更适合走客户端所在网络的本地 DNS”，而不是默认公网 nameserver。
# 2) 这里刻意不包含 localhost / *.localhost：这类名字更依赖本机 hosts/回环语义，
#    直接转发给局域网 DNS 并不能稳定解决问题，反而容易制造“为什么 127.0.0.1 还要查外部 DNS”的误解。
# 3) 当用户在同目录补充 template.local-dns-servers.txt 时，这些域名会优先落到用户声明的本地 DNS。
LOCAL_DNS_POLICY_BASELINE = [
    "+.local",
    "+.localdomain",
    "+.lan",
    "+.home.arpa",
    "+.internal",
    "+.test",
    "host.docker.internal",
    "gateway.docker.internal",
    "+.docker.internal",
    "kubernetes.default.svc",
    "+.svc",
    "+.svc.cluster.local",
]

# fake-ip 过滤基线：覆盖开发机常见的本地域名、容器互联域名与基础系统探测域名。
# 这份基线不追求“一次性全覆盖”，而是降低默认故障率，并给后续增量维护提供稳定起点。
FAKE_IP_FILTER_BASELINE = [
    "localhost",
    "*.localhost",
    "*.local",
    "*.localdomain",
    "*.lan",
    "*.home.arpa",
    "*.internal",
    "*.test",
    "host.docker.internal",
    "gateway.docker.internal",
    "*.docker.internal",
    "kubernetes.default.svc",
    "*.svc",
    "*.svc.cluster.local",
    "*.in-addr.arpa",
    "*.ip6.arpa",
    "wpad",
    "stun.*.*.*",
    "stun.*.*",
    "*.*.*.srv.nintendo.net",
    "*.*.stun.playstation.net",
    "*.*.xboxlive.com",
    "xbox.*.*.microsoft.com",
    "speedtest.cros.wr.pvp.net",
    "pool.ntp.org",
    "*.ntp.org",
    "*.ntp.org.cn",
    "*.openwrt.pool.ntp.org",
    "ntp.aliyun.com",
    "ntp.ubuntu.com",
    "ntp1.aliyun.com",
    "ntp2.aliyun.com",
    "ntp3.aliyun.com",
    "ntp4.aliyun.com",
    "ntp5.aliyun.com",
    "ntp6.aliyun.com",
    "ntp7.aliyun.com",
    "time.windows.com",
    "time.nist.gov",
    "time.ustc.edu.cn",
    "time1.cloud.tencent.com",
    "time.apple.com",
    "time.asia.apple.com",
    "time1.apple.com",
    "time2.apple.com",
    "time3.apple.com",
    "time4.apple.com",
    "time5.apple.com",
    "time6.apple.com",
    "time7.apple.com",
    "*.time.apple.com",
    "time1.aliyun.com",
    "time2.aliyun.com",
    "time3.aliyun.com",
    "time4.aliyun.com",
    "time5.aliyun.com",
    "time6.aliyun.com",
    "time7.aliyun.com",
    "time.google.com",
    "time1.google.com",
    "time2.google.com",
    "time3.google.com",
    "time4.google.com",
    "*.time.google.com",
    "*.time.edu.cn",
    "*.ipv6.microsoft.com",
    "*.msftconnecttest.com",
    "*.msftncsi.com",
]
