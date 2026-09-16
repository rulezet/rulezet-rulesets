rule TTP_XOR_QUAD_CurrentVersionRun_7edc {
  strings:
    $key_7edc = { 2d b3 [2] 09 bd [2] 22 91 [2] 0c b3 [2] 18 a8 [2] 17 b2 [2] 09 af [2] 0b ae [2] 10 a8 [2] 0c af [2] 10 80 }

  condition:
    any of them
}