rule TTP_XOR_QUAD_CurrentVersionRun_2a79 {
  strings:
    $key_2a79 = { 79 16 [2] 5d 18 [2] 76 34 [2] 58 16 [2] 4c 0d [2] 43 17 [2] 5d 0a [2] 5f 0b [2] 44 0d [2] 58 0a [2] 44 25 }

  condition:
    any of them
}