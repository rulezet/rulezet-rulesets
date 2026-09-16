rule TTP_XOR_QUAD_CurrentVersionRun_2c56 {
  strings:
    $key_2c56 = { 7f 39 [2] 5b 37 [2] 70 1b [2] 5e 39 [2] 4a 22 [2] 45 38 [2] 5b 25 [2] 59 24 [2] 42 22 [2] 5e 25 [2] 42 0a }

  condition:
    any of them
}