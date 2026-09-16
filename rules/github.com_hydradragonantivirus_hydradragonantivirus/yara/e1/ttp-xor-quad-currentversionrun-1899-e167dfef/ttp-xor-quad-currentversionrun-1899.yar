rule TTP_XOR_QUAD_CurrentVersionRun_1899 {
  strings:
    $key_1899 = { 4b f6 [2] 6f f8 [2] 44 d4 [2] 6a f6 [2] 7e ed [2] 71 f7 [2] 6f ea [2] 6d eb [2] 76 ed [2] 6a ea [2] 76 c5 }

  condition:
    any of them
}