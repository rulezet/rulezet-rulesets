rule PEiD_02398_Upack_Patch____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack_Patch -> Sign by hot_UNP]"
    ep_only     = "false"

  strings:
    $a = { 2A A3 F2 54 CE }

  condition:
    $a
}