rule TTP_XOR_QUAD_CurrentVersionRun_4899 {
  strings:
    $key_4899 = { 1b f6 [2] 3f f8 [2] 14 d4 [2] 3a f6 [2] 2e ed [2] 21 f7 [2] 3f ea [2] 3d eb [2] 26 ed [2] 3a ea [2] 26 c5 }

  condition:
    any of them
}