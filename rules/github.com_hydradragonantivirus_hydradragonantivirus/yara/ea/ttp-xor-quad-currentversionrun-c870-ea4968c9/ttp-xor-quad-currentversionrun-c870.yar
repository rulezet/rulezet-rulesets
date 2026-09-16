rule TTP_XOR_QUAD_CurrentVersionRun_c870 {
  strings:
    $key_c870 = { 9b 1f [2] bf 11 [2] 94 3d [2] ba 1f [2] ae 04 [2] a1 1e [2] bf 03 [2] bd 02 [2] a6 04 [2] ba 03 [2] a6 2c }

  condition:
    any of them
}