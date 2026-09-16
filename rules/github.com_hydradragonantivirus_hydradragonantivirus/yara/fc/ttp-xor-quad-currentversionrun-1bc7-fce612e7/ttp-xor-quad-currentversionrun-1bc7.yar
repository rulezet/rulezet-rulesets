rule TTP_XOR_QUAD_CurrentVersionRun_1bc7 {
  strings:
    $key_1bc7 = { 48 a8 [2] 6c a6 [2] 47 8a [2] 69 a8 [2] 7d b3 [2] 72 a9 [2] 6c b4 [2] 6e b5 [2] 75 b3 [2] 69 b4 [2] 75 9b }

  condition:
    any of them
}