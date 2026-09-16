rule TTP_XOR_QUAD_CurrentVersionRun_19dd {
  strings:
    $key_19dd = { 4a b2 [2] 6e bc [2] 45 90 [2] 6b b2 [2] 7f a9 [2] 70 b3 [2] 6e ae [2] 6c af [2] 77 a9 [2] 6b ae [2] 77 81 }

  condition:
    any of them
}