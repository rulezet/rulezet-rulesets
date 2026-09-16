rule TTP_XOR_QUAD_CurrentVersionRun_c87e {
  strings:
    $key_c87e = { 9b 11 [2] bf 1f [2] 94 33 [2] ba 11 [2] ae 0a [2] a1 10 [2] bf 0d [2] bd 0c [2] a6 0a [2] ba 0d [2] a6 22 }

  condition:
    any of them
}