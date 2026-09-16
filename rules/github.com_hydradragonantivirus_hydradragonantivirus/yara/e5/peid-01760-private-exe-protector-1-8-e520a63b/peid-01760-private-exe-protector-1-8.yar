rule PEiD_01760_Private_EXE_Protector_1_8_ {
  meta:
    description = "[Private EXE Protector 1.8]"
    ep_only     = "false"

  strings:
    $a = { BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0 }

  condition:
    $a
}