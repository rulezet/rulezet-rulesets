rule TTP_XOR_QUAD_CurrentVersionRun_1ab5 {
  strings:
    $key_1ab5 = { 49 da [2] 6d d4 [2] 46 f8 [2] 68 da [2] 7c c1 [2] 73 db [2] 6d c6 [2] 6f c7 [2] 74 c1 [2] 68 c6 [2] 74 e9 }

  condition:
    any of them
}