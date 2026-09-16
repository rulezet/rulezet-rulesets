rule PEiD_02391_Upack_v0_39_final____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.39 final -> Sign by hot_UNP]"
    ep_only     = "false"

  strings:
    $a = { 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 }

  condition:
    $a
}