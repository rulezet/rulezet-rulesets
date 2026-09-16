rule Cobaltbaltstrike_RAW_Payload_TCP_Reverse_x64
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "21151a9c-1d15-514f-b33b-c9eff08463fb"
  strings:
        $h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
  condition:
    
    uint32(@h01+0x0100) == 0x0726774c and
    uint32(@h01+0x0111) == 0x006b8029 and
    uint32(@h01+0x012d) == 0xe0df0fea and
    uint32(@h01+0x0142) == 0x6174a599 and
    uint32(@h01+0x016b) == 0x5fc8d902 and
    uint32(@h01+0x018b) == 0xe553a458 and
    uint32(@h01+0x01a5) == 0x5fc8d902 and
    uint32(@h01+0x01c1) == 0x614d6e75
}