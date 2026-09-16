rule TTP_XOR_QUAD_CurrentVersionRun_c874 {
  strings:
    $key_c874 = { 9b 1b [2] bf 15 [2] 94 39 [2] ba 1b [2] ae 00 [2] a1 1a [2] bf 07 [2] bd 06 [2] a6 00 [2] ba 07 [2] a6 28 }

  condition:
    any of them
}