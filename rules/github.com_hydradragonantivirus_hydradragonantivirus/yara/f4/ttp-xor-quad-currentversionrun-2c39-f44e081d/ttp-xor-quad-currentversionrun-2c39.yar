rule TTP_XOR_QUAD_CurrentVersionRun_2c39 {
  strings:
    $key_2c39 = { 7f 56 [2] 5b 58 [2] 70 74 [2] 5e 56 [2] 4a 4d [2] 45 57 [2] 5b 4a [2] 59 4b [2] 42 4d [2] 5e 4a [2] 42 65 }

  condition:
    any of them
}