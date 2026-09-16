rule TTP_XOR_QUAD_CurrentVersionRun_cfef {
  strings:
    $key_cfef = { 9c 80 [2] b8 8e [2] 93 a2 [2] bd 80 [2] a9 9b [2] a6 81 [2] b8 9c [2] ba 9d [2] a1 9b [2] bd 9c [2] a1 b3 }

  condition:
    any of them
}