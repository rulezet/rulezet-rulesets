rule TTP_XOR_QUAD_CurrentVersionRun_7edd {
  strings:
    $key_7edd = { 2d b2 [2] 09 bc [2] 22 90 [2] 0c b2 [2] 18 a9 [2] 17 b3 [2] 09 ae [2] 0b af [2] 10 a9 [2] 0c ae [2] 10 81 }

  condition:
    any of them
}