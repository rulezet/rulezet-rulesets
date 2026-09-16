rule TTP_XOR_QUAD_CurrentVersionRun_6425 {
  strings:
    $key_6425 = { 37 4a [2] 13 44 [2] 38 68 [2] 16 4a [2] 02 51 [2] 0d 4b [2] 13 56 [2] 11 57 [2] 0a 51 [2] 16 56 [2] 0a 79 }

  condition:
    any of them
}