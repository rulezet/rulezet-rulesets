rule TTP_XOR_QUAD_CurrentVersionRun_cafd {
  strings:
    $key_cafd = { 99 92 [2] bd 9c [2] 96 b0 [2] b8 92 [2] ac 89 [2] a3 93 [2] bd 8e [2] bf 8f [2] a4 89 [2] b8 8e [2] a4 a1 }

  condition:
    any of them
}