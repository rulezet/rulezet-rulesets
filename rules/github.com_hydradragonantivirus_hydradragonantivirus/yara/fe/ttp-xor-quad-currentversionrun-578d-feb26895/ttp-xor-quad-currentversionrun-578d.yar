rule TTP_XOR_QUAD_CurrentVersionRun_578d {
  strings:
    $key_578d = { 04 e2 [2] 20 ec [2] 0b c0 [2] 25 e2 [2] 31 f9 [2] 3e e3 [2] 20 fe [2] 22 ff [2] 39 f9 [2] 25 fe [2] 39 d1 }

  condition:
    any of them
}