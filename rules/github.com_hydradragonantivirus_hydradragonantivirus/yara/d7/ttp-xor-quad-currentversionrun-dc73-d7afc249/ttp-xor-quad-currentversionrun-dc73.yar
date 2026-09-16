rule TTP_XOR_QUAD_CurrentVersionRun_dc73 {
  strings:
    $key_dc73 = { 8f 1c [2] ab 12 [2] 80 3e [2] ae 1c [2] ba 07 [2] b5 1d [2] ab 00 [2] a9 01 [2] b2 07 [2] ae 00 [2] b2 2f }

  condition:
    any of them
}