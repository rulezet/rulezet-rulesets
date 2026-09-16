rule TTP_XOR_QUAD_CurrentVersionRun_779c {
  strings:
    $key_779c = { 24 f3 [2] 00 fd [2] 2b d1 [2] 05 f3 [2] 11 e8 [2] 1e f2 [2] 00 ef [2] 02 ee [2] 19 e8 [2] 05 ef [2] 19 c0 }

  condition:
    any of them
}