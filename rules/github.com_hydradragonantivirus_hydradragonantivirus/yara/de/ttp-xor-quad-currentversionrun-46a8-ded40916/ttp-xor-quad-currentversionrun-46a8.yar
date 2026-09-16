rule TTP_XOR_QUAD_CurrentVersionRun_46a8 {
  strings:
    $key_46a8 = { 15 c7 [2] 31 c9 [2] 1a e5 [2] 34 c7 [2] 20 dc [2] 2f c6 [2] 31 db [2] 33 da [2] 28 dc [2] 34 db [2] 28 f4 }

  condition:
    any of them
}