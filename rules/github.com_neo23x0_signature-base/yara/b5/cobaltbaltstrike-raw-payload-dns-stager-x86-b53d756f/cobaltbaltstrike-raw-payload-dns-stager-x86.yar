rule Cobaltbaltstrike_RAW_Payload_dns_stager_x86
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "817c4a72-7be1-5a58-987d-fe203d7778ea"
  strings:
        $h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
  condition:
    
    uint32(@h01+0x00a3) == 0xe553a458 and
    uint32(@h01+0x00bd) == 0x0726774c and
    uint32(@h01+0x012f) == 0xc99cc96a and
    uint32(@h01+0x0198) == 0x56a2b5f0 and
    uint32(@h01+0x01a4) == 0xe035f044 and
    uint32(@h01+0x01e4) == 0xcc8e00f4
}