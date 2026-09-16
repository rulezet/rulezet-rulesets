rule TTP_XOR_QUAD_CurrentVersionRun_c8ee {
  strings:
    $key_c8ee = { 9b 81 [2] bf 8f [2] 94 a3 [2] ba 81 [2] ae 9a [2] a1 80 [2] bf 9d [2] bd 9c [2] a6 9a [2] ba 9d [2] a6 b2 }

  condition:
    any of them
}