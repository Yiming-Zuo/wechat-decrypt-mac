import re


def format_msg_type(t):
    return {
        1: '文本', 3: '图片', 34: '语音', 42: '名片',
        43: '视频', 47: '表情', 48: '位置', 49: '链接/文件',
        50: '通话', 62: '短视频', 10000: '系统', 10002: '撤回',
    }.get(t, f'type={t}')


def _format_appmsg(text):
    if not text:
        return '[链接/文件]'

    def _xml_val(tag):
        m = re.search(rf'<{tag}[^>]*>(.*?)</{tag}>', text, re.DOTALL)
        return m.group(1).strip() if m else ''

    title = _xml_val('title')
    sub_type = _xml_val('type')

    if sub_type == '57':
        ref_name = _xml_val('displayname')
        ref_content = _xml_val('content')
        ref_content = ref_content.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        if ref_content.startswith('<'):
            ref_content = ''
        ref_part = f"{ref_name}: {ref_content}" if ref_name and ref_content else ref_name or ref_content or ''
        result = f"[引用] {title}" if title else "[引用]"
        if ref_part:
            result += f" | {ref_part}"
        return result

    if sub_type == '6':
        return f"[文件] {title}" if title else "[文件]"

    if sub_type == '5':
        appname = _xml_val('appname')
        result = f"[链接] {title}" if title else "[链接]"
        if appname:
            result += f" - {appname}"
        return result

    return f"[链接/文件] {title}" if title else "[链接/文件]"


def format_summary(msg_type, summary):
    if msg_type == 1:
        return summary or ''
    if msg_type == 49:
        return _format_appmsg(summary)
    if msg_type == 10000:
        return summary or f"[{format_msg_type(msg_type)}]"
    return f"[{format_msg_type(msg_type)}]"
