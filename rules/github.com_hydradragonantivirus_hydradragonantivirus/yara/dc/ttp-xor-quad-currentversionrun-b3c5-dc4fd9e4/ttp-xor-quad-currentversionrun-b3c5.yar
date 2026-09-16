rule TTP_XOR_QUAD_CurrentVersionRun_b3c5 {
  strings:
    $key_b3c5 = { e0 aa [2] c4 a4 [2] ef 88 [2] c1 aa [2] d5 b1 [2] da ab [2] c4 b6 [2] c6 b7 [2] dd b1 [2] c1 b6 [2] dd 99 }

  condition:
    any of them
}