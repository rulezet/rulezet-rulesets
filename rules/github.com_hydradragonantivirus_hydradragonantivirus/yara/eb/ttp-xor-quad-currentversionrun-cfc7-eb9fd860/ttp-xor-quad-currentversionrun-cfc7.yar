rule TTP_XOR_QUAD_CurrentVersionRun_cfc7 {
  strings:
    $key_cfc7 = { 9c a8 [2] b8 a6 [2] 93 8a [2] bd a8 [2] a9 b3 [2] a6 a9 [2] b8 b4 [2] ba b5 [2] a1 b3 [2] bd b4 [2] a1 9b }

  condition:
    any of them
}