rule TTP_XOR_QUAD_CurrentVersionRun_c875 {
  strings:
    $key_c875 = { 9b 1a [2] bf 14 [2] 94 38 [2] ba 1a [2] ae 01 [2] a1 1b [2] bf 06 [2] bd 07 [2] a6 01 [2] ba 06 [2] a6 29 }

  condition:
    any of them
}