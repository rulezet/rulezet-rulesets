rule TTP_XOR_QUAD_CurrentVersionRun_4bc7 {
  strings:
    $key_4bc7 = { 18 a8 [2] 3c a6 [2] 17 8a [2] 39 a8 [2] 2d b3 [2] 22 a9 [2] 3c b4 [2] 3e b5 [2] 25 b3 [2] 39 b4 [2] 25 9b }

  condition:
    any of them
}