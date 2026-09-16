rule TTP_XOR_QUAD_CurrentVersionRun_028d {
  strings:
    $key_028d = { 51 e2 [2] 75 ec [2] 5e c0 [2] 70 e2 [2] 64 f9 [2] 6b e3 [2] 75 fe [2] 77 ff [2] 6c f9 [2] 70 fe [2] 6c d1 }

  condition:
    any of them
}