rule TTP_XOR_QUAD_CurrentVersionRun_d45e {
  strings:
    $key_d45e = { 87 31 [2] a3 3f [2] 88 13 [2] a6 31 [2] b2 2a [2] bd 30 [2] a3 2d [2] a1 2c [2] ba 2a [2] a6 2d [2] ba 02 }

  condition:
    any of them
}