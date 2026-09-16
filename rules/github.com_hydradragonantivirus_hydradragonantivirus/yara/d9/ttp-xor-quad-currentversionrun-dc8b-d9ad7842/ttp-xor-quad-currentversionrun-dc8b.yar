rule TTP_XOR_QUAD_CurrentVersionRun_dc8b {
  strings:
    $key_dc8b = { 8f e4 [2] ab ea [2] 80 c6 [2] ae e4 [2] ba ff [2] b5 e5 [2] ab f8 [2] a9 f9 [2] b2 ff [2] ae f8 [2] b2 d7 }

  condition:
    any of them
}