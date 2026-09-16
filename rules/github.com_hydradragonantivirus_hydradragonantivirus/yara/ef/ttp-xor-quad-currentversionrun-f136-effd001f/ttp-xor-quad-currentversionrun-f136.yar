rule TTP_XOR_QUAD_CurrentVersionRun_f136 {
  strings:
    $key_f136 = { a2 59 [2] 86 57 [2] ad 7b [2] 83 59 [2] 97 42 [2] 98 58 [2] 86 45 [2] 84 44 [2] 9f 42 [2] 83 45 [2] 9f 6a }

  condition:
    any of them
}