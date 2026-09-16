rule TTP_XOR_QUAD_CurrentVersionRun_cffa {
  strings:
    $key_cffa = { 9c 95 [2] b8 9b [2] 93 b7 [2] bd 95 [2] a9 8e [2] a6 94 [2] b8 89 [2] ba 88 [2] a1 8e [2] bd 89 [2] a1 a6 }

  condition:
    any of them
}