rule TTP_XOR_QUAD_CurrentVersionRun_12d6 {
  strings:
    $key_12d6 = { 41 b9 [2] 65 b7 [2] 4e 9b [2] 60 b9 [2] 74 a2 [2] 7b b8 [2] 65 a5 [2] 67 a4 [2] 7c a2 [2] 60 a5 [2] 7c 8a }

  condition:
    any of them
}