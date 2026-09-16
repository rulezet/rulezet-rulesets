rule TTP_XOR_QUAD_CurrentVersionRun_c68d {
  strings:
    $key_c68d = { 95 e2 [2] b1 ec [2] 9a c0 [2] b4 e2 [2] a0 f9 [2] af e3 [2] b1 fe [2] b3 ff [2] a8 f9 [2] b4 fe [2] a8 d1 }

  condition:
    any of them
}