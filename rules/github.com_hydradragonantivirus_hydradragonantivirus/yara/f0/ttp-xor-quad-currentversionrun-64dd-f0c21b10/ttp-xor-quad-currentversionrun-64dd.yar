rule TTP_XOR_QUAD_CurrentVersionRun_64dd {
  strings:
    $key_64dd = { 37 b2 [2] 13 bc [2] 38 90 [2] 16 b2 [2] 02 a9 [2] 0d b3 [2] 13 ae [2] 11 af [2] 0a a9 [2] 16 ae [2] 0a 81 }

  condition:
    any of them
}