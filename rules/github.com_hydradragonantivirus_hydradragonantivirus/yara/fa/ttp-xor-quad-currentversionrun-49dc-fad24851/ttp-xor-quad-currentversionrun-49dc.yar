rule TTP_XOR_QUAD_CurrentVersionRun_49dc {
  strings:
    $key_49dc = { 1a b3 [2] 3e bd [2] 15 91 [2] 3b b3 [2] 2f a8 [2] 20 b2 [2] 3e af [2] 3c ae [2] 27 a8 [2] 3b af [2] 27 80 }

  condition:
    any of them
}