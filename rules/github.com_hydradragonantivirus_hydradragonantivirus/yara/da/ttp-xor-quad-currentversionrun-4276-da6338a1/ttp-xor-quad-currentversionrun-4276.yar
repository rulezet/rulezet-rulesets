rule TTP_XOR_QUAD_CurrentVersionRun_4276 {
  strings:
    $key_4276 = { 11 19 [2] 35 17 [2] 1e 3b [2] 30 19 [2] 24 02 [2] 2b 18 [2] 35 05 [2] 37 04 [2] 2c 02 [2] 30 05 [2] 2c 2a }

  condition:
    any of them
}