rule TTP_XOR_QUAD_CurrentVersionRun_0bc7 {
  strings:
    $key_0bc7 = { 58 a8 [2] 7c a6 [2] 57 8a [2] 79 a8 [2] 6d b3 [2] 62 a9 [2] 7c b4 [2] 7e b5 [2] 65 b3 [2] 79 b4 [2] 65 9b }

  condition:
    any of them
}