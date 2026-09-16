rule TTP_XOR_QUAD_CurrentVersionRun_d38c {
  strings:
    $key_d38c = { 80 e3 [2] a4 ed [2] 8f c1 [2] a1 e3 [2] b5 f8 [2] ba e2 [2] a4 ff [2] a6 fe [2] bd f8 [2] a1 ff [2] bd d0 }

  condition:
    any of them
}