rule TTP_XOR_QUAD_CurrentVersionRun_c4d5 {
  strings:
    $key_c4d5 = { 97 ba [2] b3 b4 [2] 98 98 [2] b6 ba [2] a2 a1 [2] ad bb [2] b3 a6 [2] b1 a7 [2] aa a1 [2] b6 a6 [2] aa 89 }

  condition:
    any of them
}