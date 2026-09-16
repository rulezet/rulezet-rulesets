rule TTP_XOR_QUAD_CurrentVersionRun_421b {
  strings:
    $key_421b = { 11 74 [2] 35 7a [2] 1e 56 [2] 30 74 [2] 24 6f [2] 2b 75 [2] 35 68 [2] 37 69 [2] 2c 6f [2] 30 68 [2] 2c 47 }

  condition:
    any of them
}