rule PEiD_02121_SoftProtect____SoftProtect_by_ru_ {
  meta:
    description = "[SoftProtect -> SoftProtect.by.ru]"
    ep_only     = "true"

  strings:
    $a = { E8 0C 15 00 00 8D 85 2F 14 00 00 C7 00 00 00 00 00 E8 29 0F 00 00 E8 F6 14 00 00 8D 85 20 01 00 00 50 E8 AA 16 00 00 83 }

  condition:
    $a
}