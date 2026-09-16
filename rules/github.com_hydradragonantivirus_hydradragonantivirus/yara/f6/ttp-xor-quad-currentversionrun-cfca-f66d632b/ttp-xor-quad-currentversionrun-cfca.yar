rule TTP_XOR_QUAD_CurrentVersionRun_cfca {
  strings:
    $key_cfca = { 9c a5 [2] b8 ab [2] 93 87 [2] bd a5 [2] a9 be [2] a6 a4 [2] b8 b9 [2] ba b8 [2] a1 be [2] bd b9 [2] a1 96 }

  condition:
    any of them
}