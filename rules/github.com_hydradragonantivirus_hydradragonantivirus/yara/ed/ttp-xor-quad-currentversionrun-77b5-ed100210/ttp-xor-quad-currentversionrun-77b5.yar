rule TTP_XOR_QUAD_CurrentVersionRun_77b5 {
  strings:
    $key_77b5 = { 24 da [2] 00 d4 [2] 2b f8 [2] 05 da [2] 11 c1 [2] 1e db [2] 00 c6 [2] 02 c7 [2] 19 c1 [2] 05 c6 [2] 19 e9 }

  condition:
    any of them
}