rule TTP_XOR_QUAD_CurrentVersionRun_5947 {
  strings:
    $key_5947 = { 0a 28 [2] 2e 26 [2] 05 0a [2] 2b 28 [2] 3f 33 [2] 30 29 [2] 2e 34 [2] 2c 35 [2] 37 33 [2] 2b 34 [2] 37 1b }

  condition:
    any of them
}