rule TTP_XOR_QUAD_CurrentVersionRun_dbc7 {
  strings:
    $key_dbc7 = { 88 a8 [2] ac a6 [2] 87 8a [2] a9 a8 [2] bd b3 [2] b2 a9 [2] ac b4 [2] ae b5 [2] b5 b3 [2] a9 b4 [2] b5 9b }

  condition:
    any of them
}