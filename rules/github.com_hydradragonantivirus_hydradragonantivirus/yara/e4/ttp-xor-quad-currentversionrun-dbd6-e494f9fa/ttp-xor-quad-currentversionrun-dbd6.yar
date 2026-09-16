rule TTP_XOR_QUAD_CurrentVersionRun_dbd6 {
  strings:
    $key_dbd6 = { 88 b9 [2] ac b7 [2] 87 9b [2] a9 b9 [2] bd a2 [2] b2 b8 [2] ac a5 [2] ae a4 [2] b5 a2 [2] a9 a5 [2] b5 8a }

  condition:
    any of them
}