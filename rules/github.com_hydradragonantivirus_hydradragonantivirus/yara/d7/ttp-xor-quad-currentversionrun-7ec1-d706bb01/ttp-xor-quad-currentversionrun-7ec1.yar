rule TTP_XOR_QUAD_CurrentVersionRun_7ec1 {
  strings:
    $key_7ec1 = { 2d ae [2] 09 a0 [2] 22 8c [2] 0c ae [2] 18 b5 [2] 17 af [2] 09 b2 [2] 0b b3 [2] 10 b5 [2] 0c b2 [2] 10 9d }

  condition:
    any of them
}