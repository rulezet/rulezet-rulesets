rule TTP_XOR_QUAD_CurrentVersionRun_298d {
  strings:
    $key_298d = { 7a e2 [2] 5e ec [2] 75 c0 [2] 5b e2 [2] 4f f9 [2] 40 e3 [2] 5e fe [2] 5c ff [2] 47 f9 [2] 5b fe [2] 47 d1 }

  condition:
    any of them
}