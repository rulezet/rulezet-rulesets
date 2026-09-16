rule TTP_XOR_QUAD_CurrentVersionRun_1ab4 {
  strings:
    $key_1ab4 = { 49 db [2] 6d d5 [2] 46 f9 [2] 68 db [2] 7c c0 [2] 73 da [2] 6d c7 [2] 6f c6 [2] 74 c0 [2] 68 c7 [2] 74 e8 }

  condition:
    any of them
}