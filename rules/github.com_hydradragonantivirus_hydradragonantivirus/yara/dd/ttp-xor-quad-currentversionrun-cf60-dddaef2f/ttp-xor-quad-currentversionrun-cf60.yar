rule TTP_XOR_QUAD_CurrentVersionRun_cf60 {
  strings:
    $key_cf60 = { 9c 0f [2] b8 01 [2] 93 2d [2] bd 0f [2] a9 14 [2] a6 0e [2] b8 13 [2] ba 12 [2] a1 14 [2] bd 13 [2] a1 3c }

  condition:
    any of them
}