rule TTP_XOR_QUAD_CurrentVersionRun_c868 {
  strings:
    $key_c868 = { 9b 07 [2] bf 09 [2] 94 25 [2] ba 07 [2] ae 1c [2] a1 06 [2] bf 1b [2] bd 1a [2] a6 1c [2] ba 1b [2] a6 34 }

  condition:
    any of them
}