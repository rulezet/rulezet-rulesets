rule TTP_XOR_QUAD_CurrentVersionRun_a9ad {
  strings:
    $key_a9ad = { fa c2 [2] de cc [2] f5 e0 [2] db c2 [2] cf d9 [2] c0 c3 [2] de de [2] dc df [2] c7 d9 [2] db de [2] c7 f1 }

  condition:
    any of them
}