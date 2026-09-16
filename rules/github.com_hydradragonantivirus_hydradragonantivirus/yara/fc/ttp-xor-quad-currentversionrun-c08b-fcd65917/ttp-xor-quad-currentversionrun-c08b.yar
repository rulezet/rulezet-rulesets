rule TTP_XOR_QUAD_CurrentVersionRun_c08b {
  strings:
    $key_c08b = { 93 e4 [2] b7 ea [2] 9c c6 [2] b2 e4 [2] a6 ff [2] a9 e5 [2] b7 f8 [2] b5 f9 [2] ae ff [2] b2 f8 [2] ae d7 }

  condition:
    any of them
}