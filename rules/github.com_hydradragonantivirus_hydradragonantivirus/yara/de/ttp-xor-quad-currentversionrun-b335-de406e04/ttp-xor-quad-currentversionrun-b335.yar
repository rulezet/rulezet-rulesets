rule TTP_XOR_QUAD_CurrentVersionRun_b335 {
  strings:
    $key_b335 = { e0 5a [2] c4 54 [2] ef 78 [2] c1 5a [2] d5 41 [2] da 5b [2] c4 46 [2] c6 47 [2] dd 41 [2] c1 46 [2] dd 69 }

  condition:
    any of them
}