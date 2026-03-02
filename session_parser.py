"""
解析 SessionAbstract._packed_MMSessionInfo BLOB (protobuf wire format)
无外部依赖
"""


def _read_varint(data, pos):
    result = shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, pos


def decode_protobuf(data):
    """解码 protobuf wire format，返回 {field_number: [values]}"""
    fields = {}
    pos = 0
    n = len(data)
    while pos < n:
        if pos >= n:
            break
        tag, pos = _read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x7
        if wire_type == 0:
            val, pos = _read_varint(data, pos)
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            val = data[pos:pos + length]
            pos += length
        elif wire_type == 1:
            val = data[pos:pos + 8]; pos += 8
        elif wire_type == 5:
            val = data[pos:pos + 4]; pos += 4
        else:
            break
        fields.setdefault(field_num, []).append(val)
    return fields


def parse_session_info(blob):
    """
    解析 _packed_MMSessionInfo BLOB，返回会话元数据字典。

    外层结构:
      field 12 (bytes) -> 会话元数据
        sub 3 (string): display_name (群名或昵称)
        sub 6 (string): remark
      field 13 (bytes) -> 最新消息
        sub 1 (varint): mesLocalID (本地自增消息ID，非消息类型)
        sub 4 (string): content (群聊格式 "wxid:\n正文")
        sub 7 (varint): messageType (标准微信消息类型: 1/3/34/49/10000 等)
    """
    result = {'summary': '', 'msg_type': 0, 'sender': '', 'display_name': '', 'remark': ''}
    if not blob or isinstance(blob, str):
        return result

    try:
        outer = decode_protobuf(bytes(blob))
    except Exception:
        return result

    for meta_bytes in outer.get(12, []):
        if not isinstance(meta_bytes, (bytes, bytearray)):
            continue
        try:
            meta = decode_protobuf(meta_bytes)
            for v in meta.get(3, []):
                if isinstance(v, (bytes, bytearray)):
                    result['display_name'] = v.decode('utf-8', errors='replace')
            for v in meta.get(6, []):
                if isinstance(v, (bytes, bytearray)):
                    result['remark'] = v.decode('utf-8', errors='replace')
        except Exception:
            pass

    for msg_bytes in outer.get(13, []):
        if not isinstance(msg_bytes, (bytes, bytearray)):
            continue
        try:
            msg = decode_protobuf(msg_bytes)
            for v in msg.get(7, []):
                if isinstance(v, int):
                    result['msg_type'] = v
            for v in msg.get(4, []):
                if isinstance(v, (bytes, bytearray)):
                    content = v.decode('utf-8', errors='replace')
                    if ':\n' in content:
                        result['sender'], result['summary'] = content.split(':\n', 1)
                    else:
                        result['summary'] = content
        except Exception:
            pass

    return result
