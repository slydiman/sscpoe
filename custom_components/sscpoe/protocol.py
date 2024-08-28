import platform
import base64
import struct
import json
import socket
import requests
import time
import hashlib
from urllib.parse import quote
from random import randrange
from .const import LOGGER

TIMES = 32  # The number of iterations is recommended to be an integer multiple of 8.
# The receiving and sending ends must be unified, otherwise it cannot be decrypted.
DELTA = 0x9E3779B9  # This is the value given by the algorithm standard and cannot be modified.
BYTES = "qazwsxedc"  # Byte encrypted random character table, cannot be modified at will


def json_to_str(o):
    return json.dumps(o, separators=(",", ":"))


def strToUtf8Bytes(s: str) -> bytes:
    return bytes(s, "utf-8")


# Convert byte array to uint array, convert 4byte to a uint, discard if less than 4byte
def byte2uint(bs: bytes) -> list[int]:
    count = int(len(bs) / 4)
    return list(struct.unpack("<" + "I" * count, bs[: count * 4]))


# Convert uint array to byte array, 1 to 4
def uint2byte(uint: list[int]) -> bytes:
    count = len(uint)
    return struct.pack("<" + "I" * count, *uint)


"""
TEA encryption algorithm
bs   Data to be encrypted (8 bytes of data)
keys Key 16 bytes (int array of length 4)
"""


def Encrypt(bs: bytes, ks: list[int]) -> bytes:
    sum = 0
    v = byte2uint(bs)
    for j in range(TIMES):
        sum += DELTA
        v[0] += ((v[1] << 4) + ks[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + ks[1])
        v[0] &= 0xFFFFFFFF
        v[1] += ((v[0] << 4) + ks[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + ks[3])
        v[1] &= 0xFFFFFFFF
    return uint2byte(v)


"""
TEA decryption algorithm
@param bs data to be encrypted (8 bytes of data)
@param keys key 16 bytes (int array of length 4)
"""


def Dencrypt(bs: bytes, ks: list[int]) -> bytes:
    sum = TIMES * DELTA
    v = byte2uint(bs)
    for j in range(TIMES):
        v[1] -= ((v[0] << 4) + ks[2]) ^ (v[0] + sum) ^ ((v[0] >> 5) + ks[3])
        v[1] &= 0xFFFFFFFF
        v[0] -= ((v[1] << 4) + ks[0]) ^ (v[1] + sum) ^ ((v[1] >> 5) + ks[1])
        v[0] &= 0xFFFFFFFF
        sum -= DELTA
    return uint2byte(v)


"""
Byte encryption
b data to be encrypted, byte
keys key 16 bytes, byte[]
index data index, int
"""


def encryptByte(b: int, keys: list[int], index: int) -> int:
    ms = strToUtf8Bytes(BYTES)
    m = ms[index % 8]
    k = keys[index % 4]
    s = b
    for j in range(TIMES):
        s += (((m << 2) + k)) ^ (((m >> 3) + k))
        s &= 0xFF
    return s


"""
Byte decryption
b data to be encrypted, byte
keys key 16 bytes, byte[]
index data index, int
"""


def dencryptByte(b: int, keys: list[int], index: int) -> int:
    ms = strToUtf8Bytes(BYTES)
    m = ms[index % 8]
    k = keys[index % 4]
    s = b
    for j in range(TIMES):
        s -= (((m << 2) + k)) ^ (((m >> 3) + k))
        s &= 0xFF
    return s


"""
TEA encryption

src data to be encrypted
key 16-byte key
return encrypted data or None
"""


def encrypt(bs: bytes, key: bytes) -> str:
    if bs is None or key is None or len(key) != 16:
        return None
    _len = len(bs)
    remain = _len % 8
    align = _len - remain
    keys = byte2uint(key)
    out = bytearray(_len)
    for f in range(0, align, 8):
        tmp = bytearray(8)
        for a in range(8):
            tmp[a] = bs[f + a]
        tmp = Encrypt(tmp, keys)
        for b in range(8):
            out[f + b] = tmp[b]

    for i in range(align, _len):
        out[i] = encryptByte(bs[i], keys, i)

    return base64.b64encode(out).decode("utf-8")


"""
TEA decryption

src data to be decrypted
key 16-byte key
return decrypted byte array or None
"""


def dencrypt(s: str, key: bytes) -> str:
    bs = base64.b64decode(s)
    if bs is None or key is None or len(key) != 16:
        return None
    _len = len(bs)
    remain = _len % 8
    align = _len - remain
    keys = byte2uint(key)
    out = bytearray(_len)
    for f in range(0, align, 8):
        tmp = bytearray(8)
        for a in range(8):
            tmp[a] = bs[f + a]
        tmp = Dencrypt(tmp, keys)
        for b in range(8):
            out[f + b] = tmp[b]

    for i in range(align, _len):
        out[i] = dencryptByte(bs[i], keys, i)

    # print(f'DEBUG: {out}')
    try:
        return str(out, encoding="utf-8")
    except:
        LOGGER.error(f"dencrypt({s}) -> invalid string {out}")
        return None


# _SSCPOE_CLOUD_API_URL = "https://www.steamemo.com/SSC_Switch/u?" # Domestic interface request address
_SSCPOE_CLOUD_API_URL = (
    "http://www.amitres.com:8080/SSC_Switch/u?"  # Foreign interface request address
)
# _SSCPOE_CLOUD_API_URL_ZW = "https://www.steamemo.com/SSC_Switch/zhw_u?" # ZW interface request address
# _SSCPOE_CLOUD_API_URL = "http://192.168.11.234:8080/SSC_Switch/u?" # Local interface request address
# _SSCPOE_CLOUD_API_URL = "https://www.sscee.com.cn:10443/SSC_Switch/u?" # Test server interface request address

SSCPOE_LOCAL_KEY = strToUtf8Bytes("EpumTpjli6zIxL1I")

SSCPOE_CLOUD_KEY = "PvuhBnEsLdqhmLlx"

SSCPOE_session = None


def SSCPOE_cloud_request(act: str, dt, key: str, uid: str):
    _key = strToUtf8Bytes(key)
    _act = None
    _dt = encrypt(strToUtf8Bytes(json_to_str(dt)), _key) if dt else "undefined"

    match act:
        case "wxl":  # WeChat login
            _act = "act=wxl&uid=null&dt="

        case "bmb":  # Bind mobile phone
            _act = "act=bmb&uid=" + uid + "&dt="

        case "prjshrwx":  # WeChat share
            _act = "act=prjshrwx&uid=" + uid + "&dt="

        case "emreg":  # email registration
            _act = "act=emreg&uid=null&dt="

        case "eml":  # Email Login
            _act = "act=eml&uid=null&dt="

        case "prjshrem":  # Email sharing
            _act = "act=prjshrem&uid=" + uid + "&dt="

        case "logout":  # Account cancellation
            _act = "act=delaccount&uid=" + uid + "&dt="

        case "alterpd":  # Change user password
            _act = "act=alterpd&uid=" + uid + "&dt="

        case "resetpd":  # Retrieve user password
            _act = "act=resetpd&uid=null&dt="

        case "getNicknameAndMobile":  # Get user nickname and mobile phone number
            _act = "act=userdet&uid=" + uid + "&dt="

        case "getCode":  # Get mobile phone verification code
            _act = "act=sendcode&uid=null&dt="

        case "altermb":  # Modify mobile phone number
            _act = "act=altermb&uid=" + uid + "&dt="

        case "mblink":  # Associated mobile phone number
            _act = "act=mblink&uid=" + uid + "&dt="

        case "prjmng":  # project management
            _act = "act=prjmng&uid=" + uid + "&dt="

        case "prjadd":  # Add item
            _act = "act=prjadd&uid=" + uid + "&dt="

        case "prjdel":  # Delete project
            _act = "act=prjdel&uid=" + uid + "&dt="

        case "prjren":  # Modify project name
            _act = "act=prjren&uid=" + uid + "&dt="

        case "prjjoin":  # Project participation information
            _act = "act=prjjoin&uid=" + uid + "&dt="

        case "prjtrf":  # Project handover
            _act = "act=prjtrf&uid=" + uid + "&dt="

        case "prjrecv":  # Project recycling
            _act = "act=prjrecv&uid=" + uid + "&dt="

        case "prjjoinren":  # Rename project participants
            _act = "act=prjjoinren&uid=" + uid + "&dt="

        case "prjstat":  # Project statistics
            _act = "act=prjstat&uid=" + uid + "&dt="

        case "prjexit":  # Withdraw from participation in the project
            _act = "act=prjexit&uid=" + uid + "&dt="

        # case 'prjnote': # Project remarks (cancelled)
        #   act ="act=prjnote&uid=" + uid + "&dt=";

        case "swadd":  # Add switch
            _act = "act=swadd&uid=" + uid + "&dt="

        case "swmng":  # Switch management
            _act = "act=swmng&uid=" + uid + "&dt="

        case "swdel":  # Remove switch
            _act = "act=swdel&uid=" + uid + "&dt="

        case "swnote":  # Switch notes
            _act = "act=swnote&uid=" + uid + "&dt="

        case "swren":  # Switch rename
            _act = "act=swren&uid=" + uid + "&dt="

        case "swdel":  # Delete switch
            _act = "act=swdel&uid=" + uid + "&dt="

        case "swpnote":  # Port remarks
            _act = "act=swpnote&uid=" + uid + "&dt="

        case "swkey":  # Get device password
            _act = "act=swkey&uid=" + uid + "&dt="

        case "swfwv":  # Server latest firmware version
            _act = "act=swfwv&uid=" + uid + "&dt="

        case "swrst":  # switch reset
            _act = "act=swrst&uid=" + uid + "&dt="

        case "swreb":  # Switch reboot
            _act = "act=swreb&uid=" + uid + "&dt="

        case "swupd":  # Firmware upgrade
            _act = "act=swupd&uid=" + uid + "&dt="

        case "swsort":  # Switch sorting
            _act = "act=swsort&uid=" + uid + "&dt="

        case "swconf":  # Switch configuration
            _act = "act=swconf&uid=" + uid + "&dt="

        case "swdet":  # Switch details
            _act = "act=swdet&uid=" + uid + "&dt="

        case "swcall":  # Device callback
            _act = "act=swcall&uid=" + uid + "&dt="

        case "swtask":  # scheduled tasks
            _act = "act=swtask&uid=" + uid + "&dt="

    if _act is None:
        LOGGER.error(f"SSCPOE_cloud_request: Invalid act {act}")
        return None

    url = _SSCPOE_CLOUD_API_URL + _act + quote(_dt)

    headers = {
        "user-agent": "Mozilla/5.0 (Linux; Android 9) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 uni-app Html5Plus/1.0 (Immersed/24.0)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }

    global SSCPOE_session
    try:
        if SSCPOE_session is None or act == "eml":
            if SSCPOE_session:
                SSCPOE_session.close()
            SSCPOE_session = requests.Session()
        response = SSCPOE_session.get(url, headers=headers)
    except Exception as e:
        LOGGER.exception(f"SSCPOE_cloud_request: act {act}: exception {e}")
        if act == "eml":
            return {"errcode": -1}
        SSCPOE_session.close()
        SSCPOE_session = None
        return None

    if response.status_code != requests.codes.ok:
        LOGGER.warning(
            f"SSCPOE_cloud_request: act {act}: response HTTP code: {response.status_code}"
        )
        return None

    data = dencrypt(response.text, _key)
    if data is None:
        LOGGER.error(
            f"SSCPOE_cloud_request: act {act}: dencrypt({response.text}) failed"
        )
        return None

    j = json.loads(data)
    if j is None:
        LOGGER.error(f"SSCPOE_cloud_request: act {act}: Invalid JSON received: {data}")
        return None

    errcode = j["errcode"]
    if errcode != 0:
        LOGGER.error(f"SSCPOE_cloud_request: act {act}: errcode: {errcode}")
        if act != "eml":
            return None

    return j


SSCPOE_errcode = {
    0: "OK",
    10002: "Multiple login",
    20003: "Invalid email",
    20004: "Invalid password",
}


def SSCPOE_cloud_login(email: str, password: str):
    eml = {
        "email": email,
        "pd": hashlib.md5(password.encode("utf-8")).hexdigest(),
    }
    j = SSCPOE_cloud_request("eml", eml, SSCPOE_CLOUD_KEY, None)
    if j is None:
        return "unknown"
    errcode = j["errcode"]
    if errcode == -1:
        return "cannot_connect"
    elif errcode == 20003:
        return "wrong_email"
    elif errcode == 20004:
        return "wrong_password"
    elif errcode != 0:
        return f"invalid auth code {errcode}"
    return None


def SSCPOE_local_syn():
    syn = ""
    for i in range(8):
        r = randrange(10 + 26 + 26)
        if r < 10:
            syn += chr(ord("0") + r)
        elif r < 10 + 26:
            syn += chr(ord("a") + r - 10)
        else:
            syn += chr(ord("A") + r - 10 - 26)
    return syn


host_ip = None

def get_host_ip():
    global host_ip
    if host_ip is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        host_ip = sock.getsockname()[0]
        sock.close()
    return host_ip


def SSCPOE_local_send(dt):
    MCAST_GRP = "239.0.0.100"
    MCAST_PORT = 10086

    host = get_host_ip()  # socket.gethostbyname(socket.gethostname())
    #LOGGER.info(f"SSCPOE_local_send: host={host}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except AttributeError:
        pass
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.bind((host if platform.system() == "Windows" else MCAST_GRP, 0))
    local_port = sock.getsockname()[1]
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_ADD_MEMBERSHIP,
        socket.inet_aton(MCAST_GRP) + socket.inet_aton(host),
    )

    syn = SSCPOE_local_syn()
    cmd = {"cmd": "calludp", "syn": syn, "data": dt}
    # LOGGER.info(f"SSCPOE_local_send: {cmd}")
    sock.sendto(
        (encrypt(strToUtf8Bytes(json_to_str(cmd)), SSCPOE_LOCAL_KEY) + "\r\n").encode(),
        (MCAST_GRP, MCAST_PORT),
    )
    sock.settimeout(1.0)
    return sock, syn


def SSCPOE_local_recv(sock, syn, log_timeout=True):
    try:
        data, addr = sock.recvfrom(1024)
        s = str(data, encoding="utf-8")
        if not s.endswith("\r\n"):
            raise ValueError("Invalid EOF")
        j = json.loads(dencrypt(s[:-2], SSCPOE_LOCAL_KEY))
        if j["ack"] != "calludp":
            raise ValueError("Invalid ack")
        if j["syn"] != syn:
            raise ValueError("Invalid syn")
        err = j.get("errcode", 0)
        # LOGGER.info(f"SSCPOE_local_recv: {j['data']}")
        return j["data"], err
    except TimeoutError:
        # if log_timeout:
        #    LOGGER.exception(f"SSCPOE_local_request: Timeout")
        return None, 0
    except Exception as e:
        LOGGER.exception(f"SSCPOE_local_request: {e}")
        return None, 0


def SSCPOE_local_search():
    sock, syn = SSCPOE_local_send({"callcmd": "search"})
    start = time.time()
    devices = []
    while time.time() < start + 3:
        d, err = SSCPOE_local_recv(sock, syn, log_timeout=False)
        if d:
            devices.append(d)
    return devices


def SSCPOE_local_request(dt):
    sock, syn = SSCPOE_local_send(dt)
    return SSCPOE_local_recv(sock, syn)


def SSCPOE_local_login(sn: str, password: str):
    j, err = SSCPOE_local_request(
        {
            "callcmd": "Security verification",
            "password": password,
            "sn": sn,
            "command": "login",
        }
    )
    if j is None:
        return "unknown"
    if j.get("login", "fail") != "success":
        return "wrong_password"
    return None
