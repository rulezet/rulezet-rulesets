rule TTP_XOR_QUAD_CurrentVersionRun_c844 {
  strings:
    $key_c844 = { 9b 2b [2] bf 25 [2] 94 09 [2] ba 2b [2] ae 30 [2] a1 2a [2] bf 37 [2] bd 36 [2] a6 30 [2] ba 37 [2] a6 18 }

  condition:
    any of them
}