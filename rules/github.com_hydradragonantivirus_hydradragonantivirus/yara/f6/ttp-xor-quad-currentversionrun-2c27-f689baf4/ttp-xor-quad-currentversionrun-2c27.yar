rule TTP_XOR_QUAD_CurrentVersionRun_2c27 {
  strings:
    $key_2c27 = { 7f 48 [2] 5b 46 [2] 70 6a [2] 5e 48 [2] 4a 53 [2] 45 49 [2] 5b 54 [2] 59 55 [2] 42 53 [2] 5e 54 [2] 42 7b }

  condition:
    any of them
}