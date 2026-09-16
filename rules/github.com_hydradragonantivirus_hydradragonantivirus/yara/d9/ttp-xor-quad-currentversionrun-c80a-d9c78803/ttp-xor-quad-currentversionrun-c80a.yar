rule TTP_XOR_QUAD_CurrentVersionRun_c80a {
  strings:
    $key_c80a = { 9b 65 [2] bf 6b [2] 94 47 [2] ba 65 [2] ae 7e [2] a1 64 [2] bf 79 [2] bd 78 [2] a6 7e [2] ba 79 [2] a6 56 }

  condition:
    any of them
}