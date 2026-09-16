rule TTP_XOR_QUAD_CurrentVersionRun_4228 {
  strings:
    $key_4228 = { 11 47 [2] 35 49 [2] 1e 65 [2] 30 47 [2] 24 5c [2] 2b 46 [2] 35 5b [2] 37 5a [2] 2c 5c [2] 30 5b [2] 2c 74 }

  condition:
    any of them
}