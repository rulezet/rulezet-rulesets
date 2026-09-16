rule TTP_XOR_QUAD_CurrentVersionRun_21d6 {
  strings:
    $key_21d6 = { 72 b9 [2] 56 b7 [2] 7d 9b [2] 53 b9 [2] 47 a2 [2] 48 b8 [2] 56 a5 [2] 54 a4 [2] 4f a2 [2] 53 a5 [2] 4f 8a }

  condition:
    any of them
}