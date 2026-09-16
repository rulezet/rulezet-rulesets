rule TTP_XOR_QUAD_CurrentVersionRun_c2c7 {
  strings:
    $key_c2c7 = { 91 a8 [2] b5 a6 [2] 9e 8a [2] b0 a8 [2] a4 b3 [2] ab a9 [2] b5 b4 [2] b7 b5 [2] ac b3 [2] b0 b4 [2] ac 9b }

  condition:
    any of them
}