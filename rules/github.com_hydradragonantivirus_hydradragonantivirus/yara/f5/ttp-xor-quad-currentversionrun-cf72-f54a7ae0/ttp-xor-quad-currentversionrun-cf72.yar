rule TTP_XOR_QUAD_CurrentVersionRun_cf72 {
  strings:
    $key_cf72 = { 9c 1d [2] b8 13 [2] 93 3f [2] bd 1d [2] a9 06 [2] a6 1c [2] b8 01 [2] ba 00 [2] a1 06 [2] bd 01 [2] a1 2e }

  condition:
    any of them
}