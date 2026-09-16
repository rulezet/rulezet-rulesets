rule TTP_XOR_QUAD_CurrentVersionRun_52a8 {
  strings:
    $key_52a8 = { 01 c7 [2] 25 c9 [2] 0e e5 [2] 20 c7 [2] 34 dc [2] 3b c6 [2] 25 db [2] 27 da [2] 3c dc [2] 20 db [2] 3c f4 }

  condition:
    any of them
}