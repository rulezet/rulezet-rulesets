rule TTP_XOR_QUAD_CurrentVersionRun_cf75 {
  strings:
    $key_cf75 = { 9c 1a [2] b8 14 [2] 93 38 [2] bd 1a [2] a9 01 [2] a6 1b [2] b8 06 [2] ba 07 [2] a1 01 [2] bd 06 [2] a1 29 }

  condition:
    any of them
}