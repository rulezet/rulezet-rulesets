rule TTP_XOR_QUAD_CurrentVersionRun_74dc {
  strings:
    $key_74dc = { 27 b3 [2] 03 bd [2] 28 91 [2] 06 b3 [2] 12 a8 [2] 1d b2 [2] 03 af [2] 01 ae [2] 1a a8 [2] 06 af [2] 1a 80 }

  condition:
    any of them
}