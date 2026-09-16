rule TTP_XOR_QUAD_CurrentVersionRun_d472 {
  strings:
    $key_d472 = { 87 1d [2] a3 13 [2] 88 3f [2] a6 1d [2] b2 06 [2] bd 1c [2] a3 01 [2] a1 00 [2] ba 06 [2] a6 01 [2] ba 2e }

  condition:
    any of them
}