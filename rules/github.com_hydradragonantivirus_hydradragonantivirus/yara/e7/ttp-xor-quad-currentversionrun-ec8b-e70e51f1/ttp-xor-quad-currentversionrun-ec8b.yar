rule TTP_XOR_QUAD_CurrentVersionRun_ec8b {
  strings:
    $key_ec8b = { bf e4 [2] 9b ea [2] b0 c6 [2] 9e e4 [2] 8a ff [2] 85 e5 [2] 9b f8 [2] 99 f9 [2] 82 ff [2] 9e f8 [2] 82 d7 }

  condition:
    any of them
}