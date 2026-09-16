rule TTP_XOR_QUAD_CurrentVersionRun_178d {
  strings:
    $key_178d = { 44 e2 [2] 60 ec [2] 4b c0 [2] 65 e2 [2] 71 f9 [2] 7e e3 [2] 60 fe [2] 62 ff [2] 79 f9 [2] 65 fe [2] 79 d1 }

  condition:
    any of them
}