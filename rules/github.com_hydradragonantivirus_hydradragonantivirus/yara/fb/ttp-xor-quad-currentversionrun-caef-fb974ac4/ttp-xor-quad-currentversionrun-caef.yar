rule TTP_XOR_QUAD_CurrentVersionRun_caef {
  strings:
    $key_caef = { 99 80 [2] bd 8e [2] 96 a2 [2] b8 80 [2] ac 9b [2] a3 81 [2] bd 9c [2] bf 9d [2] a4 9b [2] b8 9c [2] a4 b3 }

  condition:
    any of them
}