rule TTP_XOR_QUAD_CurrentVersionRun_5fc1 {
  strings:
    $key_5fc1 = { 0c ae [2] 28 a0 [2] 03 8c [2] 2d ae [2] 39 b5 [2] 36 af [2] 28 b2 [2] 2a b3 [2] 31 b5 [2] 2d b2 [2] 31 9d }

  condition:
    any of them
}