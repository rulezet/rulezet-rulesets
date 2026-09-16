rule TTP_XOR_QUAD_CurrentVersionRun_e391 {
  strings:
    $key_e391 = { b0 fe [2] 94 f0 [2] bf dc [2] 91 fe [2] 85 e5 [2] 8a ff [2] 94 e2 [2] 96 e3 [2] 8d e5 [2] 91 e2 [2] 8d cd }

  condition:
    any of them
}