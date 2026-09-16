rule TTP_XOR_QUAD_CurrentVersionRun_2c65 {
  strings:
    $key_2c65 = { 7f 0a [2] 5b 04 [2] 70 28 [2] 5e 0a [2] 4a 11 [2] 45 0b [2] 5b 16 [2] 59 17 [2] 42 11 [2] 5e 16 [2] 42 39 }

  condition:
    any of them
}