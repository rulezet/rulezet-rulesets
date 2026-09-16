rule TTP_XOR_QUAD_CurrentVersionRun_608d {
  strings:
    $key_608d = { 33 e2 [2] 17 ec [2] 3c c0 [2] 12 e2 [2] 06 f9 [2] 09 e3 [2] 17 fe [2] 15 ff [2] 0e f9 [2] 12 fe [2] 0e d1 }

  condition:
    any of them
}