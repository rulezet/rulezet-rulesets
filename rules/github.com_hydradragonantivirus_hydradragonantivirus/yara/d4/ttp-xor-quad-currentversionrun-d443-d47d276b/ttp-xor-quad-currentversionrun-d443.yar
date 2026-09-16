rule TTP_XOR_QUAD_CurrentVersionRun_d443 {
  strings:
    $key_d443 = { 87 2c [2] a3 22 [2] 88 0e [2] a6 2c [2] b2 37 [2] bd 2d [2] a3 30 [2] a1 31 [2] ba 37 [2] a6 30 [2] ba 1f }

  condition:
    any of them
}