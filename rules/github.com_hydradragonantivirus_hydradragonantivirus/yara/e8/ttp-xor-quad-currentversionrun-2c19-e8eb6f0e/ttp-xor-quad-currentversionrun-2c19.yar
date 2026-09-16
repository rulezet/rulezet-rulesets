rule TTP_XOR_QUAD_CurrentVersionRun_2c19 {
  strings:
    $key_2c19 = { 7f 76 [2] 5b 78 [2] 70 54 [2] 5e 76 [2] 4a 6d [2] 45 77 [2] 5b 6a [2] 59 6b [2] 42 6d [2] 5e 6a [2] 42 45 }

  condition:
    any of them
}