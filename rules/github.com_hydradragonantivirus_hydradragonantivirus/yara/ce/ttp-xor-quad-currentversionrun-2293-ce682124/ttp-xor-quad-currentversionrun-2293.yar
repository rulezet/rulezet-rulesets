rule TTP_XOR_QUAD_CurrentVersionRun_2293 {
  strings:
    $key_2293 = { 71 fc [2] 55 f2 [2] 7e de [2] 50 fc [2] 44 e7 [2] 4b fd [2] 55 e0 [2] 57 e1 [2] 4c e7 [2] 50 e0 [2] 4c cf }

  condition:
    any of them
}