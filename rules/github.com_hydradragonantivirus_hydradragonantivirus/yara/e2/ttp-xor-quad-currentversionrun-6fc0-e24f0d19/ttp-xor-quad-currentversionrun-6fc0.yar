rule TTP_XOR_QUAD_CurrentVersionRun_6fc0 {
  strings:
    $key_6fc0 = { 3c af [2] 18 a1 [2] 33 8d [2] 1d af [2] 09 b4 [2] 06 ae [2] 18 b3 [2] 1a b2 [2] 01 b4 [2] 1d b3 [2] 01 9c }

  condition:
    any of them
}