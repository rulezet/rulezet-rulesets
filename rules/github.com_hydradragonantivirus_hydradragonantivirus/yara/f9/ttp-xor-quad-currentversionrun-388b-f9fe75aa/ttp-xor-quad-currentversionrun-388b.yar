rule TTP_XOR_QUAD_CurrentVersionRun_388b {
  strings:
    $key_388b = { 6b e4 [2] 4f ea [2] 64 c6 [2] 4a e4 [2] 5e ff [2] 51 e5 [2] 4f f8 [2] 4d f9 [2] 56 ff [2] 4a f8 [2] 56 d7 }

  condition:
    any of them
}