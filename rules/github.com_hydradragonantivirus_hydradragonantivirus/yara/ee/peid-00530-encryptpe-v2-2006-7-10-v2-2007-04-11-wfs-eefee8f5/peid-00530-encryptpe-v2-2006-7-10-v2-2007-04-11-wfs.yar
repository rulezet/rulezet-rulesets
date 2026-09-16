rule PEiD_00530_EncryptPE_V2_2006_7_10_V2_2007_04_11____WFS_ {
  meta:
    description = "[EncryptPE V2.2006.7.10-V2.2007.04.11 -> WFS]"
    ep_only     = "true"

  strings:
    $a = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}