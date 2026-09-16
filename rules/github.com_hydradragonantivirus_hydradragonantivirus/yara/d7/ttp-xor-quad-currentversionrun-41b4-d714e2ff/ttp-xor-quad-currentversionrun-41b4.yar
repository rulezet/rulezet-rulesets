rule TTP_XOR_QUAD_CurrentVersionRun_41b4 {
  strings:
    $key_41b4 = { 12 db [2] 36 d5 [2] 1d f9 [2] 33 db [2] 27 c0 [2] 28 da [2] 36 c7 [2] 34 c6 [2] 2f c0 [2] 33 c7 [2] 2f e8 }

  condition:
    any of them
}