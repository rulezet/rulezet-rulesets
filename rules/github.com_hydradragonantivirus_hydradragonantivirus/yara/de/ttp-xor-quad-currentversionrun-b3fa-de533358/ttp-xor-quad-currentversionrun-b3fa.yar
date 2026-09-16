rule TTP_XOR_QUAD_CurrentVersionRun_b3fa {
  strings:
    $key_b3fa = { e0 95 [2] c4 9b [2] ef b7 [2] c1 95 [2] d5 8e [2] da 94 [2] c4 89 [2] c6 88 [2] dd 8e [2] c1 89 [2] dd a6 }

  condition:
    any of them
}