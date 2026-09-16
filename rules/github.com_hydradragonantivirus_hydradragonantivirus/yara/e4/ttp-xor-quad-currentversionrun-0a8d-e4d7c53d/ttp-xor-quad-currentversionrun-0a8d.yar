rule TTP_XOR_QUAD_CurrentVersionRun_0a8d {
  strings:
    $key_0a8d = { 59 e2 [2] 7d ec [2] 56 c0 [2] 78 e2 [2] 6c f9 [2] 63 e3 [2] 7d fe [2] 7f ff [2] 64 f9 [2] 78 fe [2] 64 d1 }

  condition:
    any of them
}