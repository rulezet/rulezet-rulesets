rule TTP_XOR_QUAD_CurrentVersionRun_2bd6 {
  strings:
    $key_2bd6 = { 78 b9 [2] 5c b7 [2] 77 9b [2] 59 b9 [2] 4d a2 [2] 42 b8 [2] 5c a5 [2] 5e a4 [2] 45 a2 [2] 59 a5 [2] 45 8a }

  condition:
    any of them
}