"""Подробный опрос железа: SoC/CPU, GPU, память, накопители, дисплей, сеть.

Один shell-вызов (HW_COMMAND) собирает всё разом: системные свойства,
/proc/cpuinfo, cpufreq, информацию GLES (GPU), device-tree (модель платы
и compatible-строки), блочные устройства и разделы, meminfo, df, батарею,
сетевые интерфейсы, термальные зоны, ядро. Парсеры — чистые функции,
покрытые тестами (scripts/test_hw_info.py).

Декодеры превращают машинные коды в человекочитаемые модели:
  sun50iw9p1 -> Allwinner H616/H313/H618/H700, petrel -> H6,
  gxl -> Amlogic S905X/D/W, 0xd03 -> Cortex-A53, aarch64 -> ARMv8-A 64-бит.
Таблицы соответствий сверены по реальным прошивкам ТВ-приставок и
исходникам ядер (sunxi BSP, mainline device-tree, u-boot README).
Сами значения — технические термины без перевода; подписи и пояснения
формирует ui/adb_toolkit.py через i18n.

Модуль не зависит от PySide6 и может использоваться из тестов напрямую.
"""

import re

from .adb_actions import (ActionError,  # noqa: F401 — для удобства импортов
                          _sections, parse_uptime, parse_wm, shell)

# ---------------------------------------------------------------- команда
# Все данные — за одно подключение: на медленном Wi-Fi ADB это заметно
# быстрее, чем серия вызовов. Циклы for — POSIX sh (mksh на Android).
HW_COMMAND = (
    "echo ==PROPS; getprop; "
    "echo ==CPUINFO; cat /proc/cpuinfo 2>/dev/null; "
    "echo ==FREQ; "
    "for d in /sys/devices/system/cpu/cpu[0-9]*; do "
    "[ -d \"$d/cpufreq\" ] && echo \"${d##*cpu} "
    "$(cat $d/cpufreq/cpuinfo_min_freq 2>/dev/null) "
    "$(cat $d/cpufreq/cpuinfo_max_freq 2>/dev/null) "
    "$(cat $d/cpufreq/scaling_cur_freq 2>/dev/null) "
    "$(cat $d/cpufreq/scaling_governor 2>/dev/null)\"; done; "
    "echo ==GOVS; cat /sys/devices/system/cpu/cpu0/cpufreq/"
    "scaling_available_governors 2>/dev/null; "
    "echo ==GLES; dumpsys SurfaceFlinger 2>/dev/null | grep -m 2 GLES; "
    "echo ==DT; cat /proc/device-tree/model 2>/dev/null; echo; "
    "cat /proc/device-tree/compatible 2>/dev/null | tr '\\0' '\\n'; "
    "echo ==PLATFORM; ls /sys/devices/platform/ 2>/dev/null | "
    "grep -iE 'sun|meson|rk|mt|hi3|tegra|chip|nand|mmc|emmc|cedar|mali|gpu' "
    "| head -20; "
    "echo ==BLOCK; "
    "for b in /sys/block/mmcblk* /sys/block/nand*; do [ -e \"$b\" ] && "
    "echo \"${b##*/} $(cat $b/device/name 2>/dev/null) "
    "$(cat $b/size 2>/dev/null)\"; done; "
    "echo ==PARTS; cat /proc/partitions 2>/dev/null; "
    "echo ==MEM; cat /proc/meminfo 2>/dev/null; "
    "echo ==DF; df -k -P 2>/dev/null; "
    "echo ==DISPLAY; wm size 2>/dev/null; wm density 2>/dev/null; "
    "dumpsys display 2>/dev/null | grep -m 3 -iE 'refreshrate|refresh rate'; "
    "echo ==BATTERY; dumpsys battery 2>/dev/null; "
    "echo ==NET; ip link show 2>/dev/null; echo ---; "
    "ip -f inet addr show 2>/dev/null || netcfg 2>/dev/null; "
    "echo ==THERMAL; "
    "for z in /sys/class/thermal/thermal_zone*; do [ -e \"$z/type\" ] && "
    "echo \"${z##*/} $(cat $z/type 2>/dev/null) "
    "$(cat $z/temp 2>/dev/null)\"; done; "
    "echo ==FEATURES; pm list features 2>/dev/null; "
    "echo ==KERNEL; cat /proc/version 2>/dev/null; uname -m 2>/dev/null; "
    "echo ==UP; cat /proc/uptime 2>/dev/null; "
    "echo ==END"
)


def read_hw(host: str, port: int = 5555, timeout: float = 30.0) -> dict:
    """Полный опрос железа одним shell-вызовом. См. описание модуля."""
    text = shell(host, HW_COMMAND, port, timeout)
    sec = _sections(text)

    props = parse_props(sec.get("PROPS", ""))
    cpuinfo = parse_cpuinfo(sec.get("CPUINFO", ""))
    dt = parse_dt(sec.get("DT", ""))

    hw = {
        "props": props,
        "cpuinfo": cpuinfo,
        "cpufreq": parse_cpufreq(sec.get("FREQ", "")),
        "gpu": parse_gles(sec.get("GLES", "")),
        "dt": dt,
        "platform": [line.strip() for line
                     in sec.get("PLATFORM", "").splitlines() if line.strip()],
        "block": parse_block(sec.get("BLOCK", "")),
        "partitions": parse_partitions(sec.get("PARTS", "")),
        "memory": parse_meminfo_ext(sec.get("MEM", "")),
        "storage": parse_df_all(sec.get("DF", "")),
        "display": parse_display(sec.get("DISPLAY", "")),
        "battery": parse_battery_ext(sec.get("BATTERY", "")),
        "net": parse_net(sec.get("NET", "")),
        "thermal": parse_thermal_zones(sec.get("THERMAL", "")),
        "features": parse_features(sec.get("FEATURES", "")),
        "kernel": parse_kernel(sec.get("KERNEL", "")),
        "soc": decode_soc(props, dt, cpuinfo),
    }
    govs = sec.get("GOVS", "").split()
    if govs:
        hw["governors_available"] = govs
    up = parse_uptime(sec.get("UP", ""))
    if up:
        hw["uptime_sec"] = up
    return hw


# ---------------------------------------------------------------- свойства
def parse_props(text: str) -> dict:
    """Вывод getprop ('[ключ]: [значение]') -> словарь."""
    out = {}
    for line in (text or "").splitlines():
        match = re.match(r"^\[(.*?)\]:\s\[(.*)\]\s*$", line.strip())
        if match:
            out[match.group(1)] = match.group(2)
    return out


# ---------------------------------------------------------------- CPU
def parse_cpuinfo(text: str) -> dict:
    """/proc/cpuinfo -> {cores, hardware, model_name, features, cores_detail,
    bogo}. cores_detail — список уникальных пар (implementer, part) с числом
    ядер: [('0x41', '0xd03', 4)]."""
    cores = 0
    hardware = ""
    model_name = ""
    features: list = []
    pairs: list = []           # (implementer, part) по порядку ядер
    bogo: list = []
    impl = ""
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "processor":
            cores += 1
        elif key == "Hardware":
            hardware = value
        elif key == "model name":
            model_name = value
        elif key == "Features":
            features = value.split()
        elif key == "CPU implementer":
            impl = value.lower()
        elif key == "CPU part":
            if value:
                pairs.append((impl, value.lower()))
        elif key == "BogoMIPS":
            try:
                bogo.append(float(value))
            except ValueError:
                pass
    detail = []
    for item in pairs:
        if item not in [(d[0], d[1]) for d in detail]:
            detail.append((item[0], item[1], pairs.count(item)))
    return {"cores": cores, "hardware": hardware, "model_name": model_name,
            "features": features, "cores_detail": detail,
            "bogo": bogo[0] if bogo else None}


# Декодер ARM-ядер: implementer + "CPU part" (главный идентификатор ядра).
# Значения — из документации ARM (ARM Architecture Reference Manual,
# MIDR_EL1.PartNum); покрывают всё, что встречается в ТВ-приставках.
CPU_IMPLEMENTERS = {
    "0x41": "ARM",
    "0x43": "Cavium",
    "0x48": "HiSilicon",
    "0x4e": "NVIDIA",
    "0x50": "Applied Micro / Ampere",
    "0x51": "Qualcomm",
    "0x53": "Samsung",
    "0x56": "Marvell",
    "0x61": "Apple",
    "0x66": "Faraday",
    "0x69": "Intel",
}

CPU_PARTS = {
    "0x41": {  # ARM
        "0xc05": "Cortex-A5", "0xc07": "Cortex-A7", "0xc08": "Cortex-A8",
        "0xc09": "Cortex-A9", "0xc0d": "Cortex-A12", "0xc0e": "Cortex-A17",
        "0xc0f": "Cortex-A15", "0xd01": "Cortex-A32", "0xd03": "Cortex-A53",
        "0xd04": "Cortex-A35", "0xd05": "Cortex-A55", "0xd06": "Cortex-A65",
        "0xd07": "Cortex-A57", "0xd08": "Cortex-A72", "0xd09": "Cortex-A73",
        "0xd0a": "Cortex-A75", "0xd0b": "Cortex-A76",
        "0xd0c": "Neoverse-N1", "0xd0d": "Cortex-A77",
        "0xd0e": "Cortex-A76AE", "0xd40": "Neoverse-V1",
        "0xd41": "Cortex-A78", "0xd42": "Cortex-A78AE",
        "0xd44": "Cortex-X1", "0xd46": "Cortex-A510",
        "0xd47": "Cortex-A710", "0xd48": "Cortex-X2",
        "0xd4d": "Cortex-A520", "0xd4e": "Cortex-A720",
        "0xd4f": "Cortex-X3",
    },
    "0x51": {  # Qualcomm (фирменные ядра)
        "0x00f": "Scorpion", "0x02d": "Scorpion", "0x04d": "Krait",
        "0x06f": "Krait", "0x205": "Kryo (Silver)", "0x211": "Kryo (Gold)",
        "0x800": "Kryo 260/280 (Gold)", "0x801": "Kryo 260/280 (Silver)",
        "0x802": "Kryo 385 (Gold)", "0x803": "Kryo 385 (Silver)",
        "0xc00": "Falkor", "0xc01": "Saphira",
    },
    "0x4e": {"0x003": "Denver", "0x004": "Carmel"},   # NVIDIA
}


def decode_arm_core(implementer: str, part: str) -> "tuple | None":
    """('0x41', '0xd03') -> ('ARM', 'Cortex-A53'); неизвестные -> None."""
    vendor = CPU_IMPLEMENTERS.get((implementer or "").lower())
    if not vendor:
        return None
    name = CPU_PARTS.get(implementer.lower(), {}).get((part or "").lower())
    if not name:
        return None
    return vendor, name


def parse_cpufreq(text: str) -> list:
    """Строки 'N min max cur governor' -> список {core, min_khz, max_khz,
    cur_khz, governor}."""
    out = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 5 or not fields[0].isdigit():
            continue
        def khz(value):
            return int(value) if value.isdigit() else None
        out.append({"core": int(fields[0]), "min_khz": khz(fields[1]),
                    "max_khz": khz(fields[2]), "cur_khz": khz(fields[3]),
                    "governor": fields[4]})
    return out


# ---------------------------------------------------------------- SoC
# Коды платформ Allwinner: <семейство>w<код>p<N>. Сверено по BSP-исходникам
# (sunxi longan/camdroid) и прошивкам приставок:
#   sun50iw1p1 = A64/H5, sun50iw6p1 = H6, sun50iw9p1 = H616/H313/H618/H700,
#   sun8iw5p1 = A33, sun8iw6p1 = A83T, sun8iw7p1 = H3/H2+, sun9i = A80.
# petrel — код платформы H6 в Android BSP (ro.board.platform="petrel").
_SOC_RULES = (
    (r"^gxb[b]?$", "Amlogic", "S905 (GXBB)"),
    (r"^gxl$", "Amlogic", "S905X / S905D / S905W / S905L (GXL)"),
    (r"^gxm$", "Amlogic", "S912 (GXM)"),
    (r"^g12a$", "Amlogic", "S905X2 / S905D2 / S905Y2 (G12A)"),
    (r"^g12b$", "Amlogic", "S922X / A311D (G12B)"),
    (r"^sm1$", "Amlogic", "S905X3 / S905D3 / S905Y3 (SM1)"),
    (r"^sc2$", "Amlogic", "S905X4 (SC2)"),
    (r"^axg$", "Amlogic", "A113D / A113X (AXG)"),
    (r"^s4$", "Amlogic", "S4: S805X2 / S905Y4 / S905X5"),
    (r"^petrel$", "Allwinner", "H6"),
    (r"^sun4i", "Allwinner", "A10"),
    (r"^sun5i", "Allwinner", "A13 / A10s"),
    (r"^sun6i", "Allwinner", "A31"),
    (r"^sun7i", "Allwinner", "A20"),
    (r"^sun8iw5", "Allwinner", "A33"),
    (r"^sun8iw6", "Allwinner", "A83T"),
    (r"^sun8iw7", "Allwinner", "H3 / H2+"),
    (r"^sun9i", "Allwinner", "A80"),
    (r"^sun50iw1", "Allwinner", "A64 / H5"),
    (r"^sun50iw6", "Allwinner", "H6"),
    (r"^sun50iw9", "Allwinner", "H616 / H313 / H618 / H700"),
    (r"^sun50i", "Allwinner", "семейство sun50i (64-бит: A64/H5/H6/H616…)"),
    (r"^sun8i", "Allwinner", "семейство sun8i (32-бит: A33/A83T/H3…)"),
    (r"^rk322x$", "Rockchip", "RK3228 / RK3229"),
    (r"^tegra132$", "NVIDIA", "Tegra K1 (T132)"),
    (r"^tegra124$", "NVIDIA", "Tegra K1 (T124)"),
    (r"^tegra186$", "NVIDIA", "Tegra X2 (T186)"),
    (r"^tegra210$", "NVIDIA", "Tegra X1 (T210)"),
    (r"^tegra194$", "NVIDIA", "Tegra Xavier (T194)"),
    (r"^tegra234$", "NVIDIA", "Tegra Orin (T234)"),
)

# Совпадение по префиксу с заменой цифр — общий случай (rk3328, mt8163…).
# Суффиксы сохраняем целиком: Hi3798MV300, SC9832E, RK3228A.
_SOC_GENERIC = (
    (r"^rk(\d{4}[a-z0-9]*)$", "Rockchip",
     lambda m: "RK" + m.group(1).upper()),
    (r"^mt(\d{4}[a-z0-9]*)$", "MediaTek", lambda m: "MT" + m.group(1).upper()),
    (r"^msm(\d{4}[a-z0-9]*)$", "Qualcomm", lambda m: "MSM" + m.group(1)),
    (r"^apq(\d{4}[a-z0-9]*)$", "Qualcomm", lambda m: "APQ" + m.group(1)),
    (r"^sdm(\d{3}[a-z0-9]*)$", "Qualcomm", lambda m: "SDM" + m.group(1)),
    (r"^sm(\d{4})$", "Qualcomm", lambda m: "SM" + m.group(1)),
    (r"^qcs(\d{3})$", "Qualcomm", lambda m: "QCS" + m.group(1)),
    (r"^hi(\d{3,4}[a-z0-9]*)$", "HiSilicon",
     lambda m: "Hi" + m.group(1).upper()),
    (r"^rtd(\d{4}[a-z0-9]*)$", "Realtek",
     lambda m: "RTD" + m.group(1).upper()),
    (r"^sc(\d{4}[a-z0-9]*)$", "UNISOC / Spreadtrum",
     lambda m: "SC" + m.group(1).upper()),
    (r"^atm(\d{4})", "Actions Semiconductor", lambda m: "ATM" + m.group(1)),
    (r"^(exynos|s5e)(\d{4})$", "Samsung",
     lambda m: "Exynos " + m.group(2)),
)

# Точные соответствия из device-tree compatible (mainline + BSP).
_DT_COMPAT = {
    "allwinner,sun4i-a10": ("Allwinner", "A10"),
    "allwinner,sun5i-a13": ("Allwinner", "A13"),
    "allwinner,sun6i-a31": ("Allwinner", "A31"),
    "allwinner,sun7i-a20": ("Allwinner", "A20"),
    "allwinner,sun8i-a23": ("Allwinner", "A23"),
    "allwinner,sun8i-a33": ("Allwinner", "A33"),
    "allwinner,sun8i-a83t": ("Allwinner", "A83T"),
    "allwinner,sun8i-h2-plus": ("Allwinner", "H2+"),
    "allwinner,sun8i-h3": ("Allwinner", "H3"),
    "allwinner,sun9i-a80": ("Allwinner", "A80"),
    "allwinner,sun50i-a64": ("Allwinner", "A64"),
    "allwinner,sun50i-h5": ("Allwinner", "H5"),
    "allwinner,sun50i-h6": ("Allwinner", "H6"),
    "allwinner,sun50i-h616": ("Allwinner", "H616 / H313 / H618 / H700"),
    "allwinner,sun50i-h618": ("Allwinner", "H618"),
    "allwinner,sun50i-a100": ("Allwinner", "A100"),
    "allwinner,sun50i-a133": ("Allwinner", "A133"),
    "allwinner,sun50i-r329": ("Allwinner", "R329"),
    "amlogic,gxbb": ("Amlogic", "S905"),
    "amlogic,gxl": ("Amlogic", "S905X / S905D / S905W"),
    "amlogic,gxm": ("Amlogic", "S912"),
    "amlogic,g12a": ("Amlogic", "S905X2 / S905D2 / S905Y2"),
    "amlogic,g12b": ("Amlogic", "S922X / A311D"),
    "amlogic,sm1": ("Amlogic", "S905X3 / S905D3 / S905Y3"),
    "amlogic,sc2": ("Amlogic", "S905X4"),
    "amlogic,a113d": ("Amlogic", "A113D"),
    "amlogic,a113x": ("Amlogic", "A113X"),
    "rockchip,rk3228": ("Rockchip", "RK3228"),
    "rockchip,rk3229": ("Rockchip", "RK3229"),
    "rockchip,rk3328": ("Rockchip", "RK3328"),
    "rockchip,rk3368": ("Rockchip", "RK3368"),
    "rockchip,rk3399": ("Rockchip", "RK3399"),
    "rockchip,rk3566": ("Rockchip", "RK3566"),
    "rockchip,rk3568": ("Rockchip", "RK3568"),
    "rockchip,rk3588": ("Rockchip", "RK3588"),
    "mediatek,mt8163": ("MediaTek", "MT8163"),
    "mediatek,mt8173": ("MediaTek", "MT8173"),
    "mediatek,mt8695": ("MediaTek", "MT8695"),
    "nvidia,tegra210": ("NVIDIA", "Tegra X1"),
    "nvidia,tegra186": ("NVIDIA", "Tegra X2"),
    "brcm,bcm2711": ("Broadcom", "BCM2711 (Raspberry Pi 4)"),
    "brcm,bcm2837": ("Broadcom", "BCM2837 (Raspberry Pi 3)"),
}

# Snapdragon-соответствия для Qualcomm-кодов (общеизвестные).
_SNAPDRAGON = {
    "msm8909": "Snapdragon 210", "msm8916": "Snapdragon 410",
    "msm8917": "Snapdragon 425", "msm8937": "Snapdragon 430",
    "msm8953": "Snapdragon 450", "msm8996": "Snapdragon 820",
    "msm8998": "Snapdragon 835", "sdm660": "Snapdragon 660",
    "sdm670": "Snapdragon 670", "sdm845": "Snapdragon 845",
    "sm6115": "Snapdragon 680", "sm6150": "Snapdragon 675",
    "sm8150": "Snapdragon 855",
}


def decode_platform(value: str) -> "tuple | None":
    """Код платформы/железа -> (vendor, model). Неизвестное -> None."""
    value = (value or "").strip().lower()
    if not value:
        return None
    for pattern, vendor, model in _SOC_RULES:
        if re.match(pattern, value):
            return vendor, model
    for pattern, vendor, fmt in _SOC_GENERIC:
        match = re.match(pattern, value)
        if match:
            model = fmt(match)
            if value in _SNAPDRAGON:
                model += f" ({_SNAPDRAGON[value]})"
            return vendor, model
    return None


def _dt_lookup(compatible: str) -> "tuple | None":
    """'allwinner,sun50i-h616' -> ('Allwinner', 'H616 / …'); иначе None."""
    comp = (compatible or "").strip().lower()
    if comp in _DT_COMPAT:
        return _DT_COMPAT[comp]
    for pattern, vendor, fmt in _SOC_GENERIC:
        match = re.match(vendor_safe(pattern, comp), comp)
        if match:
            return vendor, fmt(match)
    # семейства по compatible (mainline-имена); sun(\d+)i — и sun50i тоже
    match = re.match(r"^allwinner,sun(\d+)i", comp)
    if match:
        family = {"4": "A10", "5": "A13 / A10s", "6": "A31", "7": "A20",
                  "9": "A80"}.get(match.group(1))
        if family:
            return "Allwinner", family
        if comp.startswith("allwinner,sun50i"):
            return "Allwinner", "семейство sun50i (64-бит)"
        return "Allwinner", "семейство sun8i (32-бит)"
    return None


def vendor_safe(pattern: str, value: str) -> str:
    """Для _dt_lookup: паттерны _SOC_GENERIC ждут чистые коды; здесь
    подставляем вендорную часть compatible (rockchip,rk3328)."""
    for vendor_prefix in ("rockchip,", "mediatek,", "amlogic,"):
        if value.startswith(vendor_prefix):
            return "^" + vendor_prefix + pattern[1:]
    return pattern  # не совпадёт, безопасно


def decode_soc(props: dict, dt: dict, cpuinfo: dict) -> list:
    """Определяет SoC по всем доступным источникам.

    Возвращает список кандидатов [{vendor, model, source}] в порядке
    достоверности: ro.soc.model (API 31+) > device-tree compatible >
    ro.board.platform > ro.hardware > ro.chipname > Hardware из cpuinfo.
    """
    results: list = []
    seen = set()

    def add(vendor, model, source):
        key = (vendor, str(model))
        if vendor and model and key not in seen:
            seen.add(key)
            results.append({"vendor": vendor, "model": str(model),
                            "source": source})

    soc_model = (props or {}).get("ro.soc.model", "")
    if soc_model:
        vendor = props.get("ro.soc.manufacturer", "")
        if not vendor:
            hit = decode_platform(soc_model)
            vendor = hit[0] if hit else ""
        add(vendor, soc_model, "ro.soc.model")
    for comp in (dt or {}).get("compatible", []):
        hit = _dt_lookup(comp)
        if hit:
            add(hit[0], hit[1], f"compatible: {comp}")
            break
    for key in ("ro.board.platform", "ro.hardware", "ro.chipname",
                "ro.product.board"):
        value = (props or {}).get(key, "")
        hit = decode_platform(value)
        if hit:
            add(hit[0], hit[1], key)
    hardware = (cpuinfo or {}).get("hardware", "")
    hit = decode_platform(hardware)
    if hit:
        add(hit[0], hit[1], "/proc/cpuinfo Hardware")
    return results


# ---------------------------------------------------------------- GPU
def decode_gpu_family(renderer: str) -> str:
    """'Mali-G31' -> 'Mali-G31 (Bifrost)'. Названия архитектур —
    собственные имена ARM/Imagination, перевод не требуется."""
    name = (renderer or "").strip()
    low = name.lower()
    if "mali" in low:
        if re.search(r"mali-4\d\d", low):
            return "Mali (Utgard)"
        if re.search(r"mali-t\d+", low):
            return "Mali (Midgard)"
        if re.search(r"mali-g(31|51|52|71|72|76)", low):
            return "Mali (Bifrost)"
        if re.search(r"mali-g(310|510)", low):
            return "Mali (Valhall, gen 2)"
        if re.search(r"mali-g(57|68|77|78)", low):
            return "Mali (Valhall)"
        if re.search(r"mali-g(610|710|615|715)", low) or "immortalis" in low:
            return "Mali (Valhall, gen 3)"
        return "Mali"
    if "powervr" in low or re.search(r"\bge\d+", low):
        if re.search(r"\bbxe|b-series", low):
            return "PowerVR (B-Series)"
        return "PowerVR (Rogue)"
    if "adreno" in low:
        return "Adreno (Qualcomm)"
    if "vivante" in low or re.search(r"\bgc\d+", low):
        return "Vivante"
    if "videocore" in low:
        return "VideoCore (Broadcom)"
    if "nvidia" in low or "tegra" in low:
        return "NVIDIA"
    if "llvmpipe" in low or "swrast" in low:
        return "software-render"   # переводится в UI (hw_gpu_software)
    return ""


def parse_gles(text: str) -> dict:
    """Строка 'GLES: <vendor>, <renderer>, <version>' из dumpsys
    SurfaceFlinger -> {vendor, renderer, version, family}."""
    match = re.search(r"GLES:\s*([^,\n]+),\s*([^,\n]+),\s*(.+)",
                      text or "", re.I)
    if not match:
        return {}
    vendor = match.group(1).strip()
    renderer = match.group(2).strip()
    version = match.group(3).strip()
    return {"vendor": vendor, "renderer": renderer, "version": version,
            "family": decode_gpu_family(renderer)}


# ---------------------------------------------------------------- память
def parse_meminfo_ext(text: str) -> dict:
    """/proc/meminfo -> {total_mb, available_mb, cached_mb, swap_total_mb,
    swap_free_mb, used_pct}."""
    def field(name):
        match = re.search(rf"^{name}:\s+(\d+)", text or "", re.M)
        return int(match.group(1)) if match else 0

    total_kb = field("MemTotal")
    available_kb = field("MemAvailable") or field("MemFree")
    cached_kb = field("Cached") + field("Buffers")
    used_pct = 0
    if total_kb:
        used_pct = max(0, min(100, int(round(
            100 * (total_kb - available_kb) / total_kb))))
    return {"total_mb": total_kb // 1024,
            "available_mb": available_kb // 1024,
            "cached_mb": cached_kb // 1024,
            "swap_total_mb": field("SwapTotal") // 1024,
            "swap_free_mb": field("SwapFree") // 1024,
            "used_pct": used_pct}


# ---------------------------------------------------------------- накопители
def parse_block(text: str) -> list:
    """'mmcblk0 BGND3R 15267840' -> [{name, chip, size_gb}].
    size — секторы по 512 байт; chip — модель eMMC-чипа (если есть)."""
    out = []
    for line in (text or "").splitlines():
        fields = line.split()
        if not fields or not re.match(r"^(mmcblk\d+|nand\w*)$", fields[0]):
            continue
        name = fields[0]
        chip = fields[1] if len(fields) > 1 and not fields[1].isdigit() else ""
        sectors = 0
        for value in fields[1:]:
            if value.isdigit():
                sectors = int(value)
                break
        size_gb = round(sectors * 512 / 1024 ** 3, 1) if sectors else None
        out.append({"name": name, "chip": chip, "size_gb": size_gb})
    return out


def parse_partitions(text: str) -> list:
    """/proc/partitions -> [{name, mb}] (только разделы mmcblk*/nand*)."""
    out = []
    for line in (text or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or not fields[0].isdigit():
            continue
        name = fields[3]
        if not re.match(r"^(mmcblk\d+p\d+|mmcblk\d+$|nand\w*)$", name):
            continue
        out.append({"name": name, "mb": int(fields[2]) // 1024})
    return out


def parse_df_all(text: str) -> list:
    """Полная таблица df -> [{mount, total_mb, used_pct}] для реальных
    файловых систем (>= 64 МБ), отсортированных по размеру по убыванию."""
    out = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 6 or not fields[1].isdigit():
            continue
        mount, use_pct, size_kb = fields[-1], fields[-2], fields[1]
        if not mount.startswith("/") or not use_pct.rstrip("%").isdigit():
            continue
        if mount.startswith("/dev"):        # tmpfs/uevent-псевдофайлы
            continue
        total_mb = int(size_kb) // 1024
        if total_mb < 64:
            continue
        out.append({"mount": mount, "total_mb": total_mb,
                    "used_pct": min(100, int(use_pct.rstrip("%")))})
    out.sort(key=lambda item: item["total_mb"], reverse=True)
    return out


# ---------------------------------------------------------------- дисплей
def parse_display(text: str) -> dict:
    """wm size/density (adb_actions.parse_wm) + частота обновления."""
    out = parse_wm(text or "")
    for match in re.finditer(r"refresh[\w ]*[:=]\s*(\d{2,3}(?:\.\d+)?)",
                             text or "", re.I):
        value = float(match.group(1))
        if 20.0 <= value <= 240.0:
            out["fps"] = value
            break
    return out


# ---------------------------------------------------------------- батарея
BATT_STATUS = {1: "unknown", 2: "charging", 3: "discharging",
               4: "not_charging", 5: "full"}
BATT_HEALTH = {1: "unknown", 2: "good", 3: "overheat", 4: "dead",
               5: "over_voltage", 6: "failure", 7: "cold"}


def parse_battery_ext(text: str) -> dict:
    """dumpsys battery -> {level, temp_c, charging, status, health,
    technology, voltage_mv} (как aa.parse_battery + детали)."""
    def num(name):
        match = re.search(rf"^\s*{name}:\s*(\d+)", text or "", re.M)
        return int(match.group(1)) if match else None

    level = num("level")
    temp = num("temperature")
    result = {
        "charging": bool(re.search(r"^\s*(AC|USB|Wireless|Dock) powered:"
                                   r"\s*true", text or "", re.M | re.I)),
        "status": BATT_STATUS.get(num("status"), ""),
        "health": BATT_HEALTH.get(num("health"), ""),
    }
    if level is not None:
        result["level"] = max(0, min(100, level))
    if temp is not None:
        result["temp_c"] = round(temp / 10.0, 1)
    match = re.search(r"^\s*technology:\s*(\S.*)$", text or "", re.M)
    if match:
        result["technology"] = match.group(1).strip()
    voltage = num("voltage")
    if voltage:
        result["voltage_mv"] = voltage
    return result


# ---------------------------------------------------------------- сеть
def parse_net(text: str) -> list:
    """'ip link show' + 'ip addr' (или netcfg) -> [{iface, mac, ips}].
    Секции разделены '---' (после него — адреса)."""
    if "---" in (text or ""):
        links_text, addrs_text = text.split("---", 1)
    else:
        links_text, addrs_text = text or "", ""
    macs = {}
    current = ""          # последний увиденный интерфейс (link/ether ниже)
    for line in (links_text or "").splitlines():
        match = re.match(r"^\s*\d+:\s+([\w.@]+):", line)
        if match:
            current = match.group(1).split("@")[0]
            continue
        match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
        if match and current:
            macs.setdefault(current, match.group(1).lower())
            current = ""
    if not macs:  # netcfg-стиль: 'wlan0  UP  192.168.1.5/24  0x00001043  aa:bb:..'
        for match in re.finditer(
                r"^\s*([\w.]+)\s+\w+.*?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})",
                links_text, re.M):
            macs.setdefault(match.group(1), match.group(2).lower())
    ips = {}
    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+"
                             r"[^\n]*?(?:\bscope global (\S+)|\bdev\s+(\S+))",
                             addrs_text or ""):
        ip, scope_iface, dev = match.groups()
        iface = scope_iface or dev or ""
        if ip.startswith("127.") or not iface:
            continue
        ips.setdefault(iface, []).append(ip)
    if not ips:  # netcfg: 'eth0  UP  192.168.1.5/24 ...'
        for match in re.finditer(
                r"^\s*([\w.]+)\s+\w+\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?\s",
                addrs_text or "", re.M):
            if not match.group(2).startswith("127."):
                ips.setdefault(match.group(1), []).append(match.group(2))
    ifaces = sorted(set(macs) | set(ips))
    return [{"iface": name, "mac": macs.get(name, ""),
             "ips": ips.get(name, [])} for name in ifaces]


# ---------------------------------------------------------------- температуры
def parse_thermal_zones(text: str) -> list:
    """'thermal_zone0 cpu_thermal 55312' -> [{zone, type, temp_c}].
    Значение в миллиградусах (55312 -> 55.3); сырые небольшие числа
    (уже градусы) проходят как есть."""
    out = []
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].startswith("thermal_zone"):
            continue
        zone, ztype, raw = fields[0], fields[1], fields[2]
        if not raw.lstrip("-").isdigit():
            continue
        value = int(raw)
        if abs(value) >= 1000:
            value = value / 1000.0
        if -40.0 <= value <= 150.0:
            out.append({"zone": zone, "type": ztype,
                        "temp_c": round(value, 1)})
    return out


# ---------------------------------------------------------------- прочее
def parse_features(text: str) -> list:
    """'pm list features' -> список android.hardware.* / …software.*."""
    out = []
    for match in re.finditer(r"^(?:feature:)?(android\.[\w.]+)",
                             text or "", re.M):
        name = match.group(1)
        if name not in out:
            out.append(name)
    return out


def parse_kernel(text: str) -> dict:
    """cat /proc/version + uname -m -> {version, raw, arch}."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    out = {"version": "", "raw": "", "arch": ""}
    for line in lines:
        match = re.match(r"Linux version\s+(\S+)\s+(.*)", line)
        if match:
            out["version"] = match.group(1)
            out["raw"] = match.group(2).strip()
            break
    for line in lines:
        if line.lower() in ("aarch64", "armv7l", "armv8l", "x86_64", "x86",
                            "i686", "i386"):
            out["arch"] = line.lower()
    return out


def parse_dt(text: str) -> dict:
    """Секция ==DT: первая строка — модель платы, дальше — compatible
    (разделённые NUL; tr на устройстве превращает их в переводы строк,
    но если tr недоступен — режем NUL сами)."""
    model = ""
    compatible = []
    for line in (text or "").replace("\x00", "\n").splitlines():
        line = line.strip()
        if not line:
            continue
        if not model and "," not in line:
            model = line
            continue
        compatible.append(line)
    return {"model": model, "compatible": compatible}
