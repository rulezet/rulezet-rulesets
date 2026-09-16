rule TTP_XOR_QUAD_CurrentVersionRun_6a8d {
  strings:
    $key_6a8d = { 39 e2 [2] 1d ec [2] 36 c0 [2] 18 e2 [2] 0c f9 [2] 03 e3 [2] 1d fe [2] 1f ff [2] 04 f9 [2] 18 fe [2] 04 d1 }

  condition:
    any of them
}