rule TTP_XOR_QUAD_CurrentVersionRun_30d6 {
  strings:
    $key_30d6 = { 63 b9 [2] 47 b7 [2] 6c 9b [2] 42 b9 [2] 56 a2 [2] 59 b8 [2] 47 a5 [2] 45 a4 [2] 5e a2 [2] 42 a5 [2] 5e 8a }

  condition:
    any of them
}