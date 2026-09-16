rule TTP_XOR_QUAD_CurrentVersionRun_4636 {
  strings:
    $key_4636 = { 15 59 [2] 31 57 [2] 1a 7b [2] 34 59 [2] 20 42 [2] 2f 58 [2] 31 45 [2] 33 44 [2] 28 42 [2] 34 45 [2] 28 6a }

  condition:
    any of them
}