rule TTP_XOR_QUAD_CurrentVersionRun_35d6 {
  strings:
    $key_35d6 = { 66 b9 [2] 42 b7 [2] 69 9b [2] 47 b9 [2] 53 a2 [2] 5c b8 [2] 42 a5 [2] 40 a4 [2] 5b a2 [2] 47 a5 [2] 5b 8a }

  condition:
    any of them
}