rule TTP_XOR_QUAD_CurrentVersionRun_ca9c {
  strings:
    $key_ca9c = { 99 f3 [2] bd fd [2] 96 d1 [2] b8 f3 [2] ac e8 [2] a3 f2 [2] bd ef [2] bf ee [2] a4 e8 [2] b8 ef [2] a4 c0 }

  condition:
    any of them
}