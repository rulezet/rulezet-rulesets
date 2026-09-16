rule TTP_XOR_QUAD_CurrentVersionRun_b0b8 {
  strings:
    $key_b0b8 = { e3 d7 [2] c7 d9 [2] ec f5 [2] c2 d7 [2] d6 cc [2] d9 d6 [2] c7 cb [2] c5 ca [2] de cc [2] c2 cb [2] de e4 }

  condition:
    any of them
}