rule TTP_XOR_QUAD_CurrentVersionRun_cfed {
  strings:
    $key_cfed = { 9c 82 [2] b8 8c [2] 93 a0 [2] bd 82 [2] a9 99 [2] a6 83 [2] b8 9e [2] ba 9f [2] a1 99 [2] bd 9e [2] a1 b1 }

  condition:
    any of them
}