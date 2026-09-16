rule TTP_XOR_QUAD_CurrentVersionRun_c842 {
  strings:
    $key_c842 = { 9b 2d [2] bf 23 [2] 94 0f [2] ba 2d [2] ae 36 [2] a1 2c [2] bf 31 [2] bd 30 [2] a6 36 [2] ba 31 [2] a6 1e }

  condition:
    any of them
}