rule TTP_XOR_QUAD_CurrentVersionRun_c85f {
  strings:
    $key_c85f = { 9b 30 [2] bf 3e [2] 94 12 [2] ba 30 [2] ae 2b [2] a1 31 [2] bf 2c [2] bd 2d [2] a6 2b [2] ba 2c [2] a6 03 }

  condition:
    any of them
}