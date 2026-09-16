rule TTP_XOR_QUAD_CurrentVersionRun_4edd {
  strings:
    $key_4edd = { 1d b2 [2] 39 bc [2] 12 90 [2] 3c b2 [2] 28 a9 [2] 27 b3 [2] 39 ae [2] 3b af [2] 20 a9 [2] 3c ae [2] 20 81 }

  condition:
    any of them
}