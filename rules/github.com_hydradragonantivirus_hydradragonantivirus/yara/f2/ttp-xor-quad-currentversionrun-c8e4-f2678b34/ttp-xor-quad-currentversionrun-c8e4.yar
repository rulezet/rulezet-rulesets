rule TTP_XOR_QUAD_CurrentVersionRun_c8e4 {
  strings:
    $key_c8e4 = { 9b 8b [2] bf 85 [2] 94 a9 [2] ba 8b [2] ae 90 [2] a1 8a [2] bf 97 [2] bd 96 [2] a6 90 [2] ba 97 [2] a6 b8 }

  condition:
    any of them
}