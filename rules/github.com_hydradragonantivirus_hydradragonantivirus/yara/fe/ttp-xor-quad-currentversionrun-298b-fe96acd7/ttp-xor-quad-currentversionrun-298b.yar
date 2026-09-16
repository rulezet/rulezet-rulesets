rule TTP_XOR_QUAD_CurrentVersionRun_298b {
  strings:
    $key_298b = { 7a e4 [2] 5e ea [2] 75 c6 [2] 5b e4 [2] 4f ff [2] 40 e5 [2] 5e f8 [2] 5c f9 [2] 47 ff [2] 5b f8 [2] 47 d7 }

  condition:
    any of them
}