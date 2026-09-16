rule TTP_XOR_QUAD_CurrentVersionRun_2a36 {
  strings:
    $key_2a36 = { 79 59 [2] 5d 57 [2] 76 7b [2] 58 59 [2] 4c 42 [2] 43 58 [2] 5d 45 [2] 5f 44 [2] 44 42 [2] 58 45 [2] 44 6a }

  condition:
    any of them
}