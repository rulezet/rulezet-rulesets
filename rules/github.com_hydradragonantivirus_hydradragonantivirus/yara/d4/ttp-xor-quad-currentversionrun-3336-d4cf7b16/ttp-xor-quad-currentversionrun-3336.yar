rule TTP_XOR_QUAD_CurrentVersionRun_3336 {
  strings:
    $key_3336 = { 60 59 [2] 44 57 [2] 6f 7b [2] 41 59 [2] 55 42 [2] 5a 58 [2] 44 45 [2] 46 44 [2] 5d 42 [2] 41 45 [2] 5d 6a }

  condition:
    any of them
}