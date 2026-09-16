rule TTP_XOR_QUAD_CurrentVersionRun_4235 {
  strings:
    $key_4235 = { 11 5a [2] 35 54 [2] 1e 78 [2] 30 5a [2] 24 41 [2] 2b 5b [2] 35 46 [2] 37 47 [2] 2c 41 [2] 30 46 [2] 2c 69 }

  condition:
    any of them
}