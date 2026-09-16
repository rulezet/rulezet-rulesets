rule TTP_XOR_QUAD_CurrentVersionRun_3e8d {
  strings:
    $key_3e8d = { 6d e2 [2] 49 ec [2] 62 c0 [2] 4c e2 [2] 58 f9 [2] 57 e3 [2] 49 fe [2] 4b ff [2] 50 f9 [2] 4c fe [2] 50 d1 }

  condition:
    any of them
}