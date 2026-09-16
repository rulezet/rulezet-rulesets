rule TTP_XOR_QUAD_CurrentVersionRun_37c6 {
  strings:
    $key_37c6 = { 64 a9 [2] 40 a7 [2] 6b 8b [2] 45 a9 [2] 51 b2 [2] 5e a8 [2] 40 b5 [2] 42 b4 [2] 59 b2 [2] 45 b5 [2] 59 9a }

  condition:
    any of them
}