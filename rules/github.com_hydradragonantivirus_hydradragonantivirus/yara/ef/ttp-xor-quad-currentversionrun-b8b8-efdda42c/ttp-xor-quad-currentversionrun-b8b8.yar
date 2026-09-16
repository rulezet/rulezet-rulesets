rule TTP_XOR_QUAD_CurrentVersionRun_b8b8 {
  strings:
    $key_b8b8 = { eb d7 [2] cf d9 [2] e4 f5 [2] ca d7 [2] de cc [2] d1 d6 [2] cf cb [2] cd ca [2] d6 cc [2] ca cb [2] d6 e4 }

  condition:
    any of them
}