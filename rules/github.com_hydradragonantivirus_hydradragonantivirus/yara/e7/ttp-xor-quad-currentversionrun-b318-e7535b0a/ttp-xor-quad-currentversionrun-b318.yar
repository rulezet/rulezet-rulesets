rule TTP_XOR_QUAD_CurrentVersionRun_b318 {
  strings:
    $key_b318 = { e0 77 [2] c4 79 [2] ef 55 [2] c1 77 [2] d5 6c [2] da 76 [2] c4 6b [2] c6 6a [2] dd 6c [2] c1 6b [2] dd 44 }

  condition:
    any of them
}