rule TTP_XOR_QUAD_CurrentVersionRun_c854 {
  strings:
    $key_c854 = { 9b 3b [2] bf 35 [2] 94 19 [2] ba 3b [2] ae 20 [2] a1 3a [2] bf 27 [2] bd 26 [2] a6 20 [2] ba 27 [2] a6 08 }

  condition:
    any of them
}