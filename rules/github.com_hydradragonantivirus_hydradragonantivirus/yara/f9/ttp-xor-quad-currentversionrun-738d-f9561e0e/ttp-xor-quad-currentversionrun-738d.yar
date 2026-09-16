rule TTP_XOR_QUAD_CurrentVersionRun_738d {
  strings:
    $key_738d = { 20 e2 [2] 04 ec [2] 2f c0 [2] 01 e2 [2] 15 f9 [2] 1a e3 [2] 04 fe [2] 06 ff [2] 1d f9 [2] 01 fe [2] 1d d1 }

  condition:
    any of them
}