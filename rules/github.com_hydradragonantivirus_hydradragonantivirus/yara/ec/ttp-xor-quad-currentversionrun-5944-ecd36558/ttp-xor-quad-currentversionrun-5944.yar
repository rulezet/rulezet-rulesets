rule TTP_XOR_QUAD_CurrentVersionRun_5944 {
  strings:
    $key_5944 = { 0a 2b [2] 2e 25 [2] 05 09 [2] 2b 2b [2] 3f 30 [2] 30 2a [2] 2e 37 [2] 2c 36 [2] 37 30 [2] 2b 37 [2] 37 18 }

  condition:
    any of them
}