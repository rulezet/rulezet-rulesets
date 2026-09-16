rule TTP_XOR_QUAD_CurrentVersionRun_52b5 {
  strings:
    $key_52b5 = { 01 da [2] 25 d4 [2] 0e f8 [2] 20 da [2] 34 c1 [2] 3b db [2] 25 c6 [2] 27 c7 [2] 3c c1 [2] 20 c6 [2] 3c e9 }

  condition:
    any of them
}