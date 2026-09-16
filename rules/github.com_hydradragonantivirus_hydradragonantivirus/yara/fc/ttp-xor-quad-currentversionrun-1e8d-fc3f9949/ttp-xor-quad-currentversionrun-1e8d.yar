rule TTP_XOR_QUAD_CurrentVersionRun_1e8d {
  strings:
    $key_1e8d = { 4d e2 [2] 69 ec [2] 42 c0 [2] 6c e2 [2] 78 f9 [2] 77 e3 [2] 69 fe [2] 6b ff [2] 70 f9 [2] 6c fe [2] 70 d1 }

  condition:
    any of them
}