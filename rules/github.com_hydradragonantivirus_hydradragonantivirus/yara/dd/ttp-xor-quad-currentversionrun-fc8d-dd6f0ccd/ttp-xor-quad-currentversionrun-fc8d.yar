rule TTP_XOR_QUAD_CurrentVersionRun_fc8d {
  strings:
    $key_fc8d = { af e2 [2] 8b ec [2] a0 c0 [2] 8e e2 [2] 9a f9 [2] 95 e3 [2] 8b fe [2] 89 ff [2] 92 f9 [2] 8e fe [2] 92 d1 }

  condition:
    any of them
}