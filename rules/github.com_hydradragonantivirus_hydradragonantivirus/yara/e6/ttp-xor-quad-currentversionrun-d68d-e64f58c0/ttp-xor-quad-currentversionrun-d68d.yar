rule TTP_XOR_QUAD_CurrentVersionRun_d68d {
  strings:
    $key_d68d = { 85 e2 [2] a1 ec [2] 8a c0 [2] a4 e2 [2] b0 f9 [2] bf e3 [2] a1 fe [2] a3 ff [2] b8 f9 [2] a4 fe [2] b8 d1 }

  condition:
    any of them
}