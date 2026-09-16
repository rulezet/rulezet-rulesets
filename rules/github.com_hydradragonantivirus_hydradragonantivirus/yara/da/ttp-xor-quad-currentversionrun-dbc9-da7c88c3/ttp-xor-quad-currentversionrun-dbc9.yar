rule TTP_XOR_QUAD_CurrentVersionRun_dbc9 {
  strings:
    $key_dbc9 = { 88 a6 [2] ac a8 [2] 87 84 [2] a9 a6 [2] bd bd [2] b2 a7 [2] ac ba [2] ae bb [2] b5 bd [2] a9 ba [2] b5 95 }

  condition:
    any of them
}