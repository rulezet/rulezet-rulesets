rule TTP_XOR_QUAD_CurrentVersionRun_b319 {
  strings:
    $key_b319 = { e0 76 [2] c4 78 [2] ef 54 [2] c1 76 [2] d5 6d [2] da 77 [2] c4 6a [2] c6 6b [2] dd 6d [2] c1 6a [2] dd 45 }

  condition:
    any of them
}