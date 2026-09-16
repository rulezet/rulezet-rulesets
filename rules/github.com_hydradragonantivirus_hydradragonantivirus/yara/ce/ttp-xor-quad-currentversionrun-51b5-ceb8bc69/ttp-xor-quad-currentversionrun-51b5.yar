rule TTP_XOR_QUAD_CurrentVersionRun_51b5 {
  strings:
    $key_51b5 = { 02 da [2] 26 d4 [2] 0d f8 [2] 23 da [2] 37 c1 [2] 38 db [2] 26 c6 [2] 24 c7 [2] 3f c1 [2] 23 c6 [2] 3f e9 }

  condition:
    any of them
}