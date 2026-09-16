rule TTP_XOR_QUAD_CurrentVersionRun_7bc6 {
  strings:
    $key_7bc6 = { 28 a9 [2] 0c a7 [2] 27 8b [2] 09 a9 [2] 1d b2 [2] 12 a8 [2] 0c b5 [2] 0e b4 [2] 15 b2 [2] 09 b5 [2] 15 9a }

  condition:
    any of them
}