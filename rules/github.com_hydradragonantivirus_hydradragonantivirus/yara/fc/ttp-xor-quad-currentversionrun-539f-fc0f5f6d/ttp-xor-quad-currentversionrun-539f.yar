rule TTP_XOR_QUAD_CurrentVersionRun_539f {
  strings:
    $key_539f = { 00 f0 [2] 24 fe [2] 0f d2 [2] 21 f0 [2] 35 eb [2] 3a f1 [2] 24 ec [2] 26 ed [2] 3d eb [2] 21 ec [2] 3d c3 }

  condition:
    any of them
}