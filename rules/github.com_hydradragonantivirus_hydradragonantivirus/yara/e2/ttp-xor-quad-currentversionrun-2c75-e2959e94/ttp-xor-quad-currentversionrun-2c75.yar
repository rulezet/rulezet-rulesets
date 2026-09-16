rule TTP_XOR_QUAD_CurrentVersionRun_2c75 {
  strings:
    $key_2c75 = { 7f 1a [2] 5b 14 [2] 70 38 [2] 5e 1a [2] 4a 01 [2] 45 1b [2] 5b 06 [2] 59 07 [2] 42 01 [2] 5e 06 [2] 42 29 }

  condition:
    any of them
}