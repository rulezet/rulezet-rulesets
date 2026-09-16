rule TTP_XOR_QUAD_CurrentVersionRun_2c77 {
  strings:
    $key_2c77 = { 7f 18 [2] 5b 16 [2] 70 3a [2] 5e 18 [2] 4a 03 [2] 45 19 [2] 5b 04 [2] 59 05 [2] 42 03 [2] 5e 04 [2] 42 2b }

  condition:
    any of them
}