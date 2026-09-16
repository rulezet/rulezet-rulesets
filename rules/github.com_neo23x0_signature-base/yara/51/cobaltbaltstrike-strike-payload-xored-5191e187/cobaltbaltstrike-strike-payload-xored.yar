rule Cobaltbaltstrike_strike_Payload_XORed
{
  meta:
    author = "Avast Threat Intel Team"
    description = "Detects CobaltStrike payloads"
    reference = "https://github.com/avast/ioc"
    id = "0e075644-e278-5c5b-bdcc-dc2d6a32ce73"
  strings:
    $h01 = { 10 ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? 61 61 61 61 }
  condition:
        uint32be(@h01+8) ^ uint32be(@h01+16) == 0xFCE88900 or
        uint32be(@h01+8) ^ uint32be(@h01+16) == 0xFC4883E4 or
        uint32be(@h01+8) ^ uint32be(@h01+16) == 0x4D5AE800 or
        uint32be(@h01+8) ^ uint32be(@h01+16) == 0x4D5A4152 or
        uint32be(@h01+8) ^ uint32be(@h01+16) == 0x90909090
}