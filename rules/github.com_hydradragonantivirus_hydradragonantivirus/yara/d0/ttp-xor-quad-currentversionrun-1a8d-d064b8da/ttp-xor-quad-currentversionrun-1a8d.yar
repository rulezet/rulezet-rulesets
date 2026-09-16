rule TTP_XOR_QUAD_CurrentVersionRun_1a8d {
  strings:
    $key_1a8d = { 49 e2 [2] 6d ec [2] 46 c0 [2] 68 e2 [2] 7c f9 [2] 73 e3 [2] 6d fe [2] 6f ff [2] 74 f9 [2] 68 fe [2] 74 d1 }

  condition:
    any of them
}