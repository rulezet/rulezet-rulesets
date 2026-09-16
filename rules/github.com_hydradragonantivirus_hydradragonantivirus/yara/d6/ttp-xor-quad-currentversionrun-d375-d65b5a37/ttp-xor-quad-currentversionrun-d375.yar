rule TTP_XOR_QUAD_CurrentVersionRun_d375 {
  strings:
    $key_d375 = { 80 1a [2] a4 14 [2] 8f 38 [2] a1 1a [2] b5 01 [2] ba 1b [2] a4 06 [2] a6 07 [2] bd 01 [2] a1 06 [2] bd 29 }

  condition:
    any of them
}