rule TTP_XOR_QUAD_CurrentVersionRun_cac6 {
  strings:
    $key_cac6 = { 99 a9 [2] bd a7 [2] 96 8b [2] b8 a9 [2] ac b2 [2] a3 a8 [2] bd b5 [2] bf b4 [2] a4 b2 [2] b8 b5 [2] a4 9a }

  condition:
    any of them
}