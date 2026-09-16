rule TTP_XOR_QUAD_CurrentVersionRun_0f8d {
  strings:
    $key_0f8d = { 5c e2 [2] 78 ec [2] 53 c0 [2] 7d e2 [2] 69 f9 [2] 66 e3 [2] 78 fe [2] 7a ff [2] 61 f9 [2] 7d fe [2] 61 d1 }

  condition:
    any of them
}