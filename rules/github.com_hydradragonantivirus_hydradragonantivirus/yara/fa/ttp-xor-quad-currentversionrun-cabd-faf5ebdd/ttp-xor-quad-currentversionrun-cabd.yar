rule TTP_XOR_QUAD_CurrentVersionRun_cabd {
  strings:
    $key_cabd = { 99 d2 [2] bd dc [2] 96 f0 [2] b8 d2 [2] ac c9 [2] a3 d3 [2] bd ce [2] bf cf [2] a4 c9 [2] b8 ce [2] a4 e1 }

  condition:
    any of them
}