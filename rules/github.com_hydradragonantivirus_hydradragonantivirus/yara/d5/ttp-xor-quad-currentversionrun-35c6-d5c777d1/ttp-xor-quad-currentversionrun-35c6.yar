rule TTP_XOR_QUAD_CurrentVersionRun_35c6 {
  strings:
    $key_35c6 = { 66 a9 [2] 42 a7 [2] 69 8b [2] 47 a9 [2] 53 b2 [2] 5c a8 [2] 42 b5 [2] 40 b4 [2] 5b b2 [2] 47 b5 [2] 5b 9a }

  condition:
    any of them
}