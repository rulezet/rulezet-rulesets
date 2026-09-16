rule TTP_XOR_QUAD_CurrentVersionRun_328d {
  strings:
    $key_328d = { 61 e2 [2] 45 ec [2] 6e c0 [2] 40 e2 [2] 54 f9 [2] 5b e3 [2] 45 fe [2] 47 ff [2] 5c f9 [2] 40 fe [2] 5c d1 }

  condition:
    any of them
}