rule TTP_XOR_QUAD_CurrentVersionRun_c497 {
  strings:
    $key_c497 = { 97 f8 [2] b3 f6 [2] 98 da [2] b6 f8 [2] a2 e3 [2] ad f9 [2] b3 e4 [2] b1 e5 [2] aa e3 [2] b6 e4 [2] aa cb }

  condition:
    any of them
}