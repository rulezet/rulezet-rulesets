rule TTP_XOR_QUAD_CurrentVersionRun_e48b {
  strings:
    $key_e48b = { b7 e4 [2] 93 ea [2] b8 c6 [2] 96 e4 [2] 82 ff [2] 8d e5 [2] 93 f8 [2] 91 f9 [2] 8a ff [2] 96 f8 [2] 8a d7 }

  condition:
    any of them
}