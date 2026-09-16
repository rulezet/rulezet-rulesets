rule TTP_XOR_QUAD_CurrentVersionRun_5e34 {
  strings:
    $key_5e34 = { 0d 5b [2] 29 55 [2] 02 79 [2] 2c 5b [2] 38 40 [2] 37 5a [2] 29 47 [2] 2b 46 [2] 30 40 [2] 2c 47 [2] 30 68 }

  condition:
    any of them
}