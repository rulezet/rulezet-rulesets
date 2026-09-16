rule TTP_XOR_QUAD_CurrentVersionRun_fb91 {
  strings:
    $key_fb91 = { a8 fe [2] 8c f0 [2] a7 dc [2] 89 fe [2] 9d e5 [2] 92 ff [2] 8c e2 [2] 8e e3 [2] 95 e5 [2] 89 e2 [2] 95 cd }

  condition:
    any of them
}