rule TTP_XOR_QUAD_CurrentVersionRun_338d {
  strings:
    $key_338d = { 60 e2 [2] 44 ec [2] 6f c0 [2] 41 e2 [2] 55 f9 [2] 5a e3 [2] 44 fe [2] 46 ff [2] 5d f9 [2] 41 fe [2] 5d d1 }

  condition:
    any of them
}