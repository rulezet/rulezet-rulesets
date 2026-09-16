rule TTP_XOR_QUAD_CurrentVersionRun_c38b {
  strings:
    $key_c38b = { 90 e4 [2] b4 ea [2] 9f c6 [2] b1 e4 [2] a5 ff [2] aa e5 [2] b4 f8 [2] b6 f9 [2] ad ff [2] b1 f8 [2] ad d7 }

  condition:
    any of them
}