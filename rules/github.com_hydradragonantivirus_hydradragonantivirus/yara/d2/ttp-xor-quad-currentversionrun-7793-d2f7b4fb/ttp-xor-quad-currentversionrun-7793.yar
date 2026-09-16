rule TTP_XOR_QUAD_CurrentVersionRun_7793 {
  strings:
    $key_7793 = { 24 fc [2] 00 f2 [2] 2b de [2] 05 fc [2] 11 e7 [2] 1e fd [2] 00 e0 [2] 02 e1 [2] 19 e7 [2] 05 e0 [2] 19 cf }

  condition:
    any of them
}