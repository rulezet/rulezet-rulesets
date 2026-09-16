rule TTP_XOR_QUAD_CurrentVersionRun_688d {
  strings:
    $key_688d = { 3b e2 [2] 1f ec [2] 34 c0 [2] 1a e2 [2] 0e f9 [2] 01 e3 [2] 1f fe [2] 1d ff [2] 06 f9 [2] 1a fe [2] 06 d1 }

  condition:
    any of them
}