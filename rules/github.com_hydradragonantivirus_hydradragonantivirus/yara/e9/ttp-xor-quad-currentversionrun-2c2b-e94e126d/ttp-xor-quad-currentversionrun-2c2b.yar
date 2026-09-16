rule TTP_XOR_QUAD_CurrentVersionRun_2c2b {
  strings:
    $key_2c2b = { 7f 44 [2] 5b 4a [2] 70 66 [2] 5e 44 [2] 4a 5f [2] 45 45 [2] 5b 58 [2] 59 59 [2] 42 5f [2] 5e 58 [2] 42 77 }

  condition:
    any of them
}