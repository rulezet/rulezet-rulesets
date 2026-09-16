rule PEiD_02493_Vcasm_Protector_1_1___1_2____vcasm_ {
  meta:
    description = "[Vcasm-Protector 1.1 - 1.2 -> vcasm]"
    ep_only     = "true"

  strings:
    $a = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D }

  condition:
    $a
}