rule TTP_XOR_QUAD_CurrentVersionRun_148d {
  strings:
    $key_148d = { 47 e2 [2] 63 ec [2] 48 c0 [2] 66 e2 [2] 72 f9 [2] 7d e3 [2] 63 fe [2] 61 ff [2] 7a f9 [2] 66 fe [2] 7a d1 }

  condition:
    any of them
}