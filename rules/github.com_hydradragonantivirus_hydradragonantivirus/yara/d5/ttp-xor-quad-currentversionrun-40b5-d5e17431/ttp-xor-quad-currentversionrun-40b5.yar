rule TTP_XOR_QUAD_CurrentVersionRun_40b5 {
  strings:
    $key_40b5 = { 13 da [2] 37 d4 [2] 1c f8 [2] 32 da [2] 26 c1 [2] 29 db [2] 37 c6 [2] 35 c7 [2] 2e c1 [2] 32 c6 [2] 2e e9 }

  condition:
    any of them
}