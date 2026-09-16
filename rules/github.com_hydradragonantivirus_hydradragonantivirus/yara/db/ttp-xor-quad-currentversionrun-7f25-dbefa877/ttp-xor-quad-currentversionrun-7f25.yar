rule TTP_XOR_QUAD_CurrentVersionRun_7f25 {
  strings:
    $key_7f25 = { 2c 4a [2] 08 44 [2] 23 68 [2] 0d 4a [2] 19 51 [2] 16 4b [2] 08 56 [2] 0a 57 [2] 11 51 [2] 0d 56 [2] 11 79 }

  condition:
    any of them
}