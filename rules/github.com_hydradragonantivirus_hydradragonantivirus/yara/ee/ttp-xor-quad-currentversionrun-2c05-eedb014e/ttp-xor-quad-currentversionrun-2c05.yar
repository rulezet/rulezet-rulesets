rule TTP_XOR_QUAD_CurrentVersionRun_2c05 {
  strings:
    $key_2c05 = { 7f 6a [2] 5b 64 [2] 70 48 [2] 5e 6a [2] 4a 71 [2] 45 6b [2] 5b 76 [2] 59 77 [2] 42 71 [2] 5e 76 [2] 42 59 }

  condition:
    any of them
}