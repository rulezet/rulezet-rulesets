rule TTP_XOR_QUAD_CurrentVersionRun_594b {
  strings:
    $key_594b = { 0a 24 [2] 2e 2a [2] 05 06 [2] 2b 24 [2] 3f 3f [2] 30 25 [2] 2e 38 [2] 2c 39 [2] 37 3f [2] 2b 38 [2] 37 17 }

  condition:
    any of them
}