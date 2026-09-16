rule TTP_XOR_QUAD_CurrentVersionRun_2f25 {
  strings:
    $key_2f25 = { 7c 4a [2] 58 44 [2] 73 68 [2] 5d 4a [2] 49 51 [2] 46 4b [2] 58 56 [2] 5a 57 [2] 41 51 [2] 5d 56 [2] 41 79 }

  condition:
    any of them
}