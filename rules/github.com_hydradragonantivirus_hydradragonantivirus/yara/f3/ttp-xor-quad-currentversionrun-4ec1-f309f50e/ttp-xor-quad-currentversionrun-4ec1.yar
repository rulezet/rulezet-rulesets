rule TTP_XOR_QUAD_CurrentVersionRun_4ec1 {
  strings:
    $key_4ec1 = { 1d ae [2] 39 a0 [2] 12 8c [2] 3c ae [2] 28 b5 [2] 27 af [2] 39 b2 [2] 3b b3 [2] 20 b5 [2] 3c b2 [2] 20 9d }

  condition:
    any of them
}