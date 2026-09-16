rule TTP_XOR_QUAD_CurrentVersionRun_1c36 {
  strings:
    $key_1c36 = { 4f 59 [2] 6b 57 [2] 40 7b [2] 6e 59 [2] 7a 42 [2] 75 58 [2] 6b 45 [2] 69 44 [2] 72 42 [2] 6e 45 [2] 72 6a }

  condition:
    any of them
}