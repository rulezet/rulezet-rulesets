rule TTP_XOR_QUAD_CurrentVersionRun_e88b {
  strings:
    $key_e88b = { bb e4 [2] 9f ea [2] b4 c6 [2] 9a e4 [2] 8e ff [2] 81 e5 [2] 9f f8 [2] 9d f9 [2] 86 ff [2] 9a f8 [2] 86 d7 }

  condition:
    any of them
}