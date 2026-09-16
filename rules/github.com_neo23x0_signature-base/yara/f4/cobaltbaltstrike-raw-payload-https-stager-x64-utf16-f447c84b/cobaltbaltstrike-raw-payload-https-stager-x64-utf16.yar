rule Cobaltbaltstrike_RAW_Payload_https_stager_x64_UTF16
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "aa93dd56-9589-5958-9711-ca2f9c763665"
  strings:
        $h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
  condition:
    uint32(@h01+0x01d5) == 0x07002600 and
    uint32(@h01+0x0205) == 0xa7007900 and
    uint32(@h01+0x0249) == 0xc6009f00 and
    uint32(@h01+0x0287) == 0x3b002e00 and
    uint32(@h01+0x02db) == 0x86009e00 and
    uint32(@h01+0x030f) == 0x7b001800 and
    uint32(@h01+0x0659) == 0x5600a200 and
    uint32(@h01+0x0691) == 0xe5005300 and
    uint32(@h01+0x06cd) == 0xe2008900
}