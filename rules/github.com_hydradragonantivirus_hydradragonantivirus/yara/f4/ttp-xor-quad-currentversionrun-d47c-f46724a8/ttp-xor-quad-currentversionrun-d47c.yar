rule TTP_XOR_QUAD_CurrentVersionRun_d47c {
  strings:
    $key_d47c = { 87 13 [2] a3 1d [2] 88 31 [2] a6 13 [2] b2 08 [2] bd 12 [2] a3 0f [2] a1 0e [2] ba 08 [2] a6 0f [2] ba 20 }

  condition:
    any of them
}