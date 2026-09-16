rule TTP_XOR_QUAD_CurrentVersionRun_b305 {
  strings:
    $key_b305 = { e0 6a [2] c4 64 [2] ef 48 [2] c1 6a [2] d5 71 [2] da 6b [2] c4 76 [2] c6 77 [2] dd 71 [2] c1 76 [2] dd 59 }

  condition:
    any of them
}