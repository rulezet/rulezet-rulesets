rule TTP_XOR_QUAD_CurrentVersionRun_4a93 {
  strings:
    $key_4a93 = { 19 fc [2] 3d f2 [2] 16 de [2] 38 fc [2] 2c e7 [2] 23 fd [2] 3d e0 [2] 3f e1 [2] 24 e7 [2] 38 e0 [2] 24 cf }

  condition:
    any of them
}