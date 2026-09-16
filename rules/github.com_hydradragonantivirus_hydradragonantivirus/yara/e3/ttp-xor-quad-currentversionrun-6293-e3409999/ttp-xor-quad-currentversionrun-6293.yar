rule TTP_XOR_QUAD_CurrentVersionRun_6293 {
  strings:
    $key_6293 = { 31 fc [2] 15 f2 [2] 3e de [2] 10 fc [2] 04 e7 [2] 0b fd [2] 15 e0 [2] 17 e1 [2] 0c e7 [2] 10 e0 [2] 0c cf }

  condition:
    any of them
}