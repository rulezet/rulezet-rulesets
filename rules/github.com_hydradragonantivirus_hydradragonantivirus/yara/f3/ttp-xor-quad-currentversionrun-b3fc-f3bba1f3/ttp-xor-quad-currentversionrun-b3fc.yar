rule TTP_XOR_QUAD_CurrentVersionRun_b3fc {
  strings:
    $key_b3fc = { e0 93 [2] c4 9d [2] ef b1 [2] c1 93 [2] d5 88 [2] da 92 [2] c4 8f [2] c6 8e [2] dd 88 [2] c1 8f [2] dd a0 }

  condition:
    any of them
}