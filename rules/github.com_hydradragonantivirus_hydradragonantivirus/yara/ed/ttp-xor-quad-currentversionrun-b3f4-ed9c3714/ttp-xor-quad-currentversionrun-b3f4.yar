rule TTP_XOR_QUAD_CurrentVersionRun_b3f4 {
  strings:
    $key_b3f4 = { e0 9b [2] c4 95 [2] ef b9 [2] c1 9b [2] d5 80 [2] da 9a [2] c4 87 [2] c6 86 [2] dd 80 [2] c1 87 [2] dd a8 }

  condition:
    any of them
}