rule TTP_XOR_QUAD_CurrentVersionRun_c81a {
  strings:
    $key_c81a = { 9b 75 [2] bf 7b [2] 94 57 [2] ba 75 [2] ae 6e [2] a1 74 [2] bf 69 [2] bd 68 [2] a6 6e [2] ba 69 [2] a6 46 }

  condition:
    any of them
}