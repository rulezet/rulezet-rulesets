rule TTP_XOR_QUAD_CurrentVersionRun_d78a {
  strings:
    $key_d78a = { 84 e5 [2] a0 eb [2] 8b c7 [2] a5 e5 [2] b1 fe [2] be e4 [2] a0 f9 [2] a2 f8 [2] b9 fe [2] a5 f9 [2] b9 d6 }

  condition:
    any of them
}