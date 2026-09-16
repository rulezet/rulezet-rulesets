rule TTP_XOR_QUAD_CurrentVersionRun_648d {
  strings:
    $key_648d = { 37 e2 [2] 13 ec [2] 38 c0 [2] 16 e2 [2] 02 f9 [2] 0d e3 [2] 13 fe [2] 11 ff [2] 0a f9 [2] 16 fe [2] 0a d1 }

  condition:
    any of them
}