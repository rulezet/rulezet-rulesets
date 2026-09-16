rule TTP_XOR_QUAD_CurrentVersionRun_408d {
  strings:
    $key_408d = { 13 e2 [2] 37 ec [2] 1c c0 [2] 32 e2 [2] 26 f9 [2] 29 e3 [2] 37 fe [2] 35 ff [2] 2e f9 [2] 32 fe [2] 2e d1 }

  condition:
    any of them
}