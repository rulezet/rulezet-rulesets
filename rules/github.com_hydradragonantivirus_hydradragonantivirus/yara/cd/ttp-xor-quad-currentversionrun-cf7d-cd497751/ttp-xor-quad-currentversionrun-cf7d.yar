rule TTP_XOR_QUAD_CurrentVersionRun_cf7d {
  strings:
    $key_cf7d = { 9c 12 [2] b8 1c [2] 93 30 [2] bd 12 [2] a9 09 [2] a6 13 [2] b8 0e [2] ba 0f [2] a1 09 [2] bd 0e [2] a1 21 }

  condition:
    any of them
}