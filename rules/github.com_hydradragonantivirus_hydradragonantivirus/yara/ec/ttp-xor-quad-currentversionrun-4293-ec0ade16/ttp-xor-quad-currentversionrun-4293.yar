rule TTP_XOR_QUAD_CurrentVersionRun_4293 {
  strings:
    $key_4293 = { 11 fc [2] 35 f2 [2] 1e de [2] 30 fc [2] 24 e7 [2] 2b fd [2] 35 e0 [2] 37 e1 [2] 2c e7 [2] 30 e0 [2] 2c cf }

  condition:
    any of them
}