rule TTP_XOR_QUAD_CurrentVersionRun_4a8c {
  strings:
    $key_4a8c = { 19 e3 [2] 3d ed [2] 16 c1 [2] 38 e3 [2] 2c f8 [2] 23 e2 [2] 3d ff [2] 3f fe [2] 24 f8 [2] 38 ff [2] 24 d0 }

  condition:
    any of them
}