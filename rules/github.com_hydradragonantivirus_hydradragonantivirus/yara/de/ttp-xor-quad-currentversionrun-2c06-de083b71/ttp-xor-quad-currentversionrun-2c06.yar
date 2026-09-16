rule TTP_XOR_QUAD_CurrentVersionRun_2c06 {
  strings:
    $key_2c06 = { 7f 69 [2] 5b 67 [2] 70 4b [2] 5e 69 [2] 4a 72 [2] 45 68 [2] 5b 75 [2] 59 74 [2] 42 72 [2] 5e 75 [2] 42 5a }

  condition:
    any of them
}