rule TTP_XOR_QUAD_CurrentVersionRun_6436 {
  strings:
    $key_6436 = { 37 59 [2] 13 57 [2] 38 7b [2] 16 59 [2] 02 42 [2] 0d 58 [2] 13 45 [2] 11 44 [2] 0a 42 [2] 16 45 [2] 0a 6a }

  condition:
    any of them
}