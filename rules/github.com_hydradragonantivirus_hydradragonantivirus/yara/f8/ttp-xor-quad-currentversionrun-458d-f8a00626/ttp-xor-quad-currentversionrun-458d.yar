rule TTP_XOR_QUAD_CurrentVersionRun_458d {
  strings:
    $key_458d = { 16 e2 [2] 32 ec [2] 19 c0 [2] 37 e2 [2] 23 f9 [2] 2c e3 [2] 32 fe [2] 30 ff [2] 2b f9 [2] 37 fe [2] 2b d1 }

  condition:
    any of them
}