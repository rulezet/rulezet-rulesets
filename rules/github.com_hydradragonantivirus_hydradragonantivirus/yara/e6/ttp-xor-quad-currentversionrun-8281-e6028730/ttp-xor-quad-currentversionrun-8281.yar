rule TTP_XOR_QUAD_CurrentVersionRun_8281 {
  strings:
    $key_8281 = { d1 ee [2] f5 e0 [2] de cc [2] f0 ee [2] e4 f5 [2] eb ef [2] f5 f2 [2] f7 f3 [2] ec f5 [2] f0 f2 [2] ec dd }

  condition:
    any of them
}