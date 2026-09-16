rule TTP_XOR_QUAD_CurrentVersionRun_6ab4 {
  strings:
    $key_6ab4 = { 39 db [2] 1d d5 [2] 36 f9 [2] 18 db [2] 0c c0 [2] 03 da [2] 1d c7 [2] 1f c6 [2] 04 c0 [2] 18 c7 [2] 04 e8 }

  condition:
    any of them
}