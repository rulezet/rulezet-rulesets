rule TTP_XOR_QUAD_CurrentVersionRun_c3b3 {
  strings:
    $key_c3b3 = { 90 dc [2] b4 d2 [2] 9f fe [2] b1 dc [2] a5 c7 [2] aa dd [2] b4 c0 [2] b6 c1 [2] ad c7 [2] b1 c0 [2] ad ef }

  condition:
    any of them
}