rule TTP_XOR_QUAD_CurrentVersionRun_798d {
  strings:
    $key_798d = { 2a e2 [2] 0e ec [2] 25 c0 [2] 0b e2 [2] 1f f9 [2] 10 e3 [2] 0e fe [2] 0c ff [2] 17 f9 [2] 0b fe [2] 17 d1 }

  condition:
    any of them
}