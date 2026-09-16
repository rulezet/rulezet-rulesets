rule TTP_XOR_QUAD_CurrentVersionRun_6336 {
  strings:
    $key_6336 = { 30 59 [2] 14 57 [2] 3f 7b [2] 11 59 [2] 05 42 [2] 0a 58 [2] 14 45 [2] 16 44 [2] 0d 42 [2] 11 45 [2] 0d 6a }

  condition:
    any of them
}