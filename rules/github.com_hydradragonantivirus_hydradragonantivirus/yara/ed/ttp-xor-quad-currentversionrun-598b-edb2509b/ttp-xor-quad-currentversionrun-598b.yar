rule TTP_XOR_QUAD_CurrentVersionRun_598b {
  strings:
    $key_598b = { 0a e4 [2] 2e ea [2] 05 c6 [2] 2b e4 [2] 3f ff [2] 30 e5 [2] 2e f8 [2] 2c f9 [2] 37 ff [2] 2b f8 [2] 37 d7 }

  condition:
    any of them
}