rule TTP_XOR_QUAD_CurrentVersionRun_4258 {
  strings:
    $key_4258 = { 11 37 [2] 35 39 [2] 1e 15 [2] 30 37 [2] 24 2c [2] 2b 36 [2] 35 2b [2] 37 2a [2] 2c 2c [2] 30 2b [2] 2c 04 }

  condition:
    any of them
}