rule TTP_XOR_QUAD_CurrentVersionRun_2c69 {
  strings:
    $key_2c69 = { 7f 06 [2] 5b 08 [2] 70 24 [2] 5e 06 [2] 4a 1d [2] 45 07 [2] 5b 1a [2] 59 1b [2] 42 1d [2] 5e 1a [2] 42 35 }

  condition:
    any of them
}