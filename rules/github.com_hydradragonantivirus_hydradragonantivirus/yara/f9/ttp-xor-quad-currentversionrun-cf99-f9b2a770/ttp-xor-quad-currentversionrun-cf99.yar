rule TTP_XOR_QUAD_CurrentVersionRun_cf99 {
  strings:
    $key_cf99 = { 9c f6 [2] b8 f8 [2] 93 d4 [2] bd f6 [2] a9 ed [2] a6 f7 [2] b8 ea [2] ba eb [2] a1 ed [2] bd ea [2] a1 c5 }

  condition:
    any of them
}