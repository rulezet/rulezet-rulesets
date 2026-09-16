rule TTP_XOR_QUAD_CurrentVersionRun_60a8 {
  strings:
    $key_60a8 = { 33 c7 [2] 17 c9 [2] 3c e5 [2] 12 c7 [2] 06 dc [2] 09 c6 [2] 17 db [2] 15 da [2] 0e dc [2] 12 db [2] 0e f4 }

  condition:
    any of them
}