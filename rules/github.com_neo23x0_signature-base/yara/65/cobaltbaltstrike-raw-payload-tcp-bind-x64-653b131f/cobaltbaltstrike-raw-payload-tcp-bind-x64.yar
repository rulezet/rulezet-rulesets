rule Cobaltbaltstrike_RAW_Payload_TCP_Bind_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "3575408a-3309-5723-a49a-9c2088d43de9"
  strings:
        $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    
    uint32(@h01+0x0100) == 0x0726774c and
    uint32(@h01+0x0111) == 0x006b8029 and
    uint32(@h01+0x012d) == 0xe0df0fea and
    uint32(@h01+0x0142) == 0x6737dbc2 and
    uint32(@h01+0x0150) == 0xff38e9b7 and
    uint32(@h01+0x0161) == 0xe13bec74 and
    uint32(@h01+0x016f) == 0x614d6e75 and
    uint32(@h01+0x0198) == 0x5fc8d902 and
    uint32(@h01+0x01b8) == 0xe553a458 and
    uint32(@h01+0x01d2) == 0x5fc8d902 and
    uint32(@h01+0x01ee) == 0x614d6e75
}