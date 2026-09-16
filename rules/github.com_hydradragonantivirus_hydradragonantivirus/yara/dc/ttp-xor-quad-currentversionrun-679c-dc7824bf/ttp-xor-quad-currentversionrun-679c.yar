rule TTP_XOR_QUAD_CurrentVersionRun_679c {
  strings:
    $key_679c = { 34 f3 [2] 10 fd [2] 3b d1 [2] 15 f3 [2] 01 e8 [2] 0e f2 [2] 10 ef [2] 12 ee [2] 09 e8 [2] 15 ef [2] 09 c0 }

  condition:
    any of them
}