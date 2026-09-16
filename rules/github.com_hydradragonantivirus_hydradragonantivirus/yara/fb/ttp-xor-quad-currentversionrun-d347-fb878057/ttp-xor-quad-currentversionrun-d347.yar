rule TTP_XOR_QUAD_CurrentVersionRun_d347 {
  strings:
    $key_d347 = { 80 28 [2] a4 26 [2] 8f 0a [2] a1 28 [2] b5 33 [2] ba 29 [2] a4 34 [2] a6 35 [2] bd 33 [2] a1 34 [2] bd 1b }

  condition:
    any of them
}