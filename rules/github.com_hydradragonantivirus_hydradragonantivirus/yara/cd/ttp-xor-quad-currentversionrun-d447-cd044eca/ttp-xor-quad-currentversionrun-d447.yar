rule TTP_XOR_QUAD_CurrentVersionRun_d447 {
  strings:
    $key_d447 = { 87 28 [2] a3 26 [2] 88 0a [2] a6 28 [2] b2 33 [2] bd 29 [2] a3 34 [2] a1 35 [2] ba 33 [2] a6 34 [2] ba 1b }

  condition:
    any of them
}