rule TTP_XOR_QUAD_CurrentVersionRun_b3f5 {
  strings:
    $key_b3f5 = { e0 9a [2] c4 94 [2] ef b8 [2] c1 9a [2] d5 81 [2] da 9b [2] c4 86 [2] c6 87 [2] dd 81 [2] c1 86 [2] dd a9 }

  condition:
    any of them
}