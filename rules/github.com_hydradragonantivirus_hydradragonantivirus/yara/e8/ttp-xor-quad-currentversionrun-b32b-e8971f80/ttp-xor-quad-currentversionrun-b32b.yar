rule TTP_XOR_QUAD_CurrentVersionRun_b32b {
  strings:
    $key_b32b = { e0 44 [2] c4 4a [2] ef 66 [2] c1 44 [2] d5 5f [2] da 45 [2] c4 58 [2] c6 59 [2] dd 5f [2] c1 58 [2] dd 77 }

  condition:
    any of them
}