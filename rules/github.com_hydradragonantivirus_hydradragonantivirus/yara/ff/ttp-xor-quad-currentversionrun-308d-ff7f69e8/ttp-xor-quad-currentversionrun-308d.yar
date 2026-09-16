rule TTP_XOR_QUAD_CurrentVersionRun_308d {
  strings:
    $key_308d = { 63 e2 [2] 47 ec [2] 6c c0 [2] 42 e2 [2] 56 f9 [2] 59 e3 [2] 47 fe [2] 45 ff [2] 5e f9 [2] 42 fe [2] 5e d1 }

  condition:
    any of them
}