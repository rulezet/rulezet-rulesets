rule TTP_XOR_QUAD_CurrentVersionRun_d475 {
  strings:
    $key_d475 = { 87 1a [2] a3 14 [2] 88 38 [2] a6 1a [2] b2 01 [2] bd 1b [2] a3 06 [2] a1 07 [2] ba 01 [2] a6 06 [2] ba 29 }

  condition:
    any of them
}