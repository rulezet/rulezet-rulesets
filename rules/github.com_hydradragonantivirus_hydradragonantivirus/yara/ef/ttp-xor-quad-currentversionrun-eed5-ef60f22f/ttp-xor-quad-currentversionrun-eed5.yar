rule TTP_XOR_QUAD_CurrentVersionRun_eed5 {
  strings:
    $key_eed5 = { bd ba [2] 99 b4 [2] b2 98 [2] 9c ba [2] 88 a1 [2] 87 bb [2] 99 a6 [2] 9b a7 [2] 80 a1 [2] 9c a6 [2] 80 89 }

  condition:
    any of them
}