rule TTP_XOR_QUAD_CurrentVersionRun_c8fd {
  strings:
    $key_c8fd = { 9b 92 [2] bf 9c [2] 94 b0 [2] ba 92 [2] ae 89 [2] a1 93 [2] bf 8e [2] bd 8f [2] a6 89 [2] ba 8e [2] a6 a1 }

  condition:
    any of them
}