rule TTP_XOR_QUAD_CurrentVersionRun_e18d {
  strings:
    $key_e18d = { b2 e2 [2] 96 ec [2] bd c0 [2] 93 e2 [2] 87 f9 [2] 88 e3 [2] 96 fe [2] 94 ff [2] 8f f9 [2] 93 fe [2] 8f d1 }

  condition:
    any of them
}