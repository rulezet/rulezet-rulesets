rule PEiD_02115_Soft_Defender_v1_0___v1_1_ {
  meta:
    description = "[Soft Defender v1.0 - v1.1]"
    ep_only     = "true"

  strings:
    $a = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 ?? ?? ?? ?? 58 05 BA 01 ?? ?? 03 C8 74 BE 75 BC E8 }

  condition:
    $a
}