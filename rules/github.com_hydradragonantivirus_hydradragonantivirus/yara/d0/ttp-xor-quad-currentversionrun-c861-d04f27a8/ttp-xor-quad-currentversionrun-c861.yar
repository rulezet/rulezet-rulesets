rule TTP_XOR_QUAD_CurrentVersionRun_c861 {
  strings:
    $key_c861 = { 9b 0e [2] bf 00 [2] 94 2c [2] ba 0e [2] ae 15 [2] a1 0f [2] bf 12 [2] bd 13 [2] a6 15 [2] ba 12 [2] a6 3d }

  condition:
    any of them
}