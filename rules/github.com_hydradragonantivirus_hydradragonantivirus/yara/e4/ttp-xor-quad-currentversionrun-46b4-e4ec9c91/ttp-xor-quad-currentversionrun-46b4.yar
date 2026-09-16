rule TTP_XOR_QUAD_CurrentVersionRun_46b4 {
  strings:
    $key_46b4 = { 15 db [2] 31 d5 [2] 1a f9 [2] 34 db [2] 20 c0 [2] 2f da [2] 31 c7 [2] 33 c6 [2] 28 c0 [2] 34 c7 [2] 28 e8 }

  condition:
    any of them
}