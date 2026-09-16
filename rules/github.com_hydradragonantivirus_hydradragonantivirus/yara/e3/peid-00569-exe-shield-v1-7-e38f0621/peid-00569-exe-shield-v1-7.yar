rule PEiD_00569_Exe_Shield_v1_7_ {
  meta:
    description = "[Exe Shield v1.7]"
    ep_only     = "true"

  strings:
    $a = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 }

  condition:
    $a
}