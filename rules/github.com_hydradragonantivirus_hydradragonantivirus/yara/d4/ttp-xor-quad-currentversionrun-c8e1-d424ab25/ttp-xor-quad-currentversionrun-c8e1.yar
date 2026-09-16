rule TTP_XOR_QUAD_CurrentVersionRun_c8e1 {
  strings:
    $key_c8e1 = { 9b 8e [2] bf 80 [2] 94 ac [2] ba 8e [2] ae 95 [2] a1 8f [2] bf 92 [2] bd 93 [2] a6 95 [2] ba 92 [2] a6 bd }

  condition:
    any of them
}