rule TTP_XOR_QUAD_CurrentVersionRun_698d {
  strings:
    $key_698d = { 3a e2 [2] 1e ec [2] 35 c0 [2] 1b e2 [2] 0f f9 [2] 00 e3 [2] 1e fe [2] 1c ff [2] 07 f9 [2] 1b fe [2] 07 d1 }

  condition:
    any of them
}