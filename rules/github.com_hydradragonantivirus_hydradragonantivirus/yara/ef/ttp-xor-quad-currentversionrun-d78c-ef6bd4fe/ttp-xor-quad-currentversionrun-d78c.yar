rule TTP_XOR_QUAD_CurrentVersionRun_d78c {
  strings:
    $key_d78c = { 84 e3 [2] a0 ed [2] 8b c1 [2] a5 e3 [2] b1 f8 [2] be e2 [2] a0 ff [2] a2 fe [2] b9 f8 [2] a5 ff [2] b9 d0 }

  condition:
    any of them
}