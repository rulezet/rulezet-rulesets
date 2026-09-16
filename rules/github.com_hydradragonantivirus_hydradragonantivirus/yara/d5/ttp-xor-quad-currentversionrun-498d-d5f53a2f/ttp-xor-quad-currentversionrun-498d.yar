rule TTP_XOR_QUAD_CurrentVersionRun_498d {
  strings:
    $key_498d = { 1a e2 [2] 3e ec [2] 15 c0 [2] 3b e2 [2] 2f f9 [2] 20 e3 [2] 3e fe [2] 3c ff [2] 27 f9 [2] 3b fe [2] 27 d1 }

  condition:
    any of them
}