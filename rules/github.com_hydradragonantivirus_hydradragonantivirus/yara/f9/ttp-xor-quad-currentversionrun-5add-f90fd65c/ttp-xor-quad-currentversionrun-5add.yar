rule TTP_XOR_QUAD_CurrentVersionRun_5add {
  strings:
    $key_5add = { 09 b2 [2] 2d bc [2] 06 90 [2] 28 b2 [2] 3c a9 [2] 33 b3 [2] 2d ae [2] 2f af [2] 34 a9 [2] 28 ae [2] 34 81 }

  condition:
    any of them
}