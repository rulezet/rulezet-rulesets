rule TTP_XOR_QUAD_CurrentVersionRun_d470 {
  strings:
    $key_d470 = { 87 1f [2] a3 11 [2] 88 3d [2] a6 1f [2] b2 04 [2] bd 1e [2] a3 03 [2] a1 02 [2] ba 04 [2] a6 03 [2] ba 2c }

  condition:
    any of them
}