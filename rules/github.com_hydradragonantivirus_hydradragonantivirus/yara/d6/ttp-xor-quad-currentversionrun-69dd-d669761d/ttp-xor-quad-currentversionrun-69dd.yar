rule TTP_XOR_QUAD_CurrentVersionRun_69dd {
  strings:
    $key_69dd = { 3a b2 [2] 1e bc [2] 35 90 [2] 1b b2 [2] 0f a9 [2] 00 b3 [2] 1e ae [2] 1c af [2] 07 a9 [2] 1b ae [2] 07 81 }

  condition:
    any of them
}