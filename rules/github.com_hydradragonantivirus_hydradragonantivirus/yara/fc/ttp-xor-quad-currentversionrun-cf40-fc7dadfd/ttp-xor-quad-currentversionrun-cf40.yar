rule TTP_XOR_QUAD_CurrentVersionRun_cf40 {
  strings:
    $key_cf40 = { 9c 2f [2] b8 21 [2] 93 0d [2] bd 2f [2] a9 34 [2] a6 2e [2] b8 33 [2] ba 32 [2] a1 34 [2] bd 33 [2] a1 1c }

  condition:
    any of them
}