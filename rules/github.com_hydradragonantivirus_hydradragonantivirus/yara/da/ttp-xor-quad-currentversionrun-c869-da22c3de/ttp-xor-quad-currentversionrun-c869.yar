rule TTP_XOR_QUAD_CurrentVersionRun_c869 {
  strings:
    $key_c869 = { 9b 06 [2] bf 08 [2] 94 24 [2] ba 06 [2] ae 1d [2] a1 07 [2] bf 1a [2] bd 1b [2] a6 1d [2] ba 1a [2] a6 35 }

  condition:
    any of them
}