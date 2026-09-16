rule TTP_XOR_QUAD_CurrentVersionRun_6736 {
  strings:
    $key_6736 = { 34 59 [2] 10 57 [2] 3b 7b [2] 15 59 [2] 01 42 [2] 0e 58 [2] 10 45 [2] 12 44 [2] 09 42 [2] 15 45 [2] 09 6a }

  condition:
    any of them
}