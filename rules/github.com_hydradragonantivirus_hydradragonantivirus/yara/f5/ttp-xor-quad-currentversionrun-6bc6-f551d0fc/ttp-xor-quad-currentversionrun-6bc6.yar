rule TTP_XOR_QUAD_CurrentVersionRun_6bc6 {
  strings:
    $key_6bc6 = { 38 a9 [2] 1c a7 [2] 37 8b [2] 19 a9 [2] 0d b2 [2] 02 a8 [2] 1c b5 [2] 1e b4 [2] 05 b2 [2] 19 b5 [2] 05 9a }

  condition:
    any of them
}