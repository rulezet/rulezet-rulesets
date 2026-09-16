rule TTP_XOR_QUAD_CurrentVersionRun_d08b {
  strings:
    $key_d08b = { 83 e4 [2] a7 ea [2] 8c c6 [2] a2 e4 [2] b6 ff [2] b9 e5 [2] a7 f8 [2] a5 f9 [2] be ff [2] a2 f8 [2] be d7 }

  condition:
    any of them
}