rule TTP_XOR_QUAD_CurrentVersionRun_c867 {
  strings:
    $key_c867 = { 9b 08 [2] bf 06 [2] 94 2a [2] ba 08 [2] ae 13 [2] a1 09 [2] bf 14 [2] bd 15 [2] a6 13 [2] ba 14 [2] a6 3b }

  condition:
    any of them
}