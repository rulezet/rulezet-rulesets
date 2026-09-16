rule TTP_XOR_QUAD_CurrentVersionRun_538d {
  strings:
    $key_538d = { 00 e2 [2] 24 ec [2] 0f c0 [2] 21 e2 [2] 35 f9 [2] 3a e3 [2] 24 fe [2] 26 ff [2] 3d f9 [2] 21 fe [2] 3d d1 }

  condition:
    any of them
}