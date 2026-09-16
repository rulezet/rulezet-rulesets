rule TTP_XOR_QUAD_CurrentVersionRun_5a8d {
  strings:
    $key_5a8d = { 09 e2 [2] 2d ec [2] 06 c0 [2] 28 e2 [2] 3c f9 [2] 33 e3 [2] 2d fe [2] 2f ff [2] 34 f9 [2] 28 fe [2] 34 d1 }

  condition:
    any of them
}