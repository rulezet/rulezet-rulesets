rule TTP_XOR_QUAD_CurrentVersionRun_c5d5 {
  strings:
    $key_c5d5 = { 96 ba [2] b2 b4 [2] 99 98 [2] b7 ba [2] a3 a1 [2] ac bb [2] b2 a6 [2] b0 a7 [2] ab a1 [2] b7 a6 [2] ab 89 }

  condition:
    any of them
}