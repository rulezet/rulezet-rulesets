rule TTP_XOR_QUAD_CurrentVersionRun_d323 {
  strings:
    $key_d323 = { 80 4c [2] a4 42 [2] 8f 6e [2] a1 4c [2] b5 57 [2] ba 4d [2] a4 50 [2] a6 51 [2] bd 57 [2] a1 50 [2] bd 7f }

  condition:
    any of them
}