rule TTP_XOR_QUAD_CurrentVersionRun_69dc {
  strings:
    $key_69dc = { 3a b3 [2] 1e bd [2] 35 91 [2] 1b b3 [2] 0f a8 [2] 00 b2 [2] 1e af [2] 1c ae [2] 07 a8 [2] 1b af [2] 07 80 }

  condition:
    any of them
}