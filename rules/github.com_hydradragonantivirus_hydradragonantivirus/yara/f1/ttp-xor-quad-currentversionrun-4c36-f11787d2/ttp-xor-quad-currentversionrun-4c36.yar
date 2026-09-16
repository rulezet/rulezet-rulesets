rule TTP_XOR_QUAD_CurrentVersionRun_4c36 {
  strings:
    $key_4c36 = { 1f 59 [2] 3b 57 [2] 10 7b [2] 3e 59 [2] 2a 42 [2] 25 58 [2] 3b 45 [2] 39 44 [2] 22 42 [2] 3e 45 [2] 22 6a }

  condition:
    any of them
}