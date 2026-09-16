rule TTP_XOR_QUAD_CurrentVersionRun_2a8d {
  strings:
    $key_2a8d = { 79 e2 [2] 5d ec [2] 76 c0 [2] 58 e2 [2] 4c f9 [2] 43 e3 [2] 5d fe [2] 5f ff [2] 44 f9 [2] 58 fe [2] 44 d1 }

  condition:
    any of them
}