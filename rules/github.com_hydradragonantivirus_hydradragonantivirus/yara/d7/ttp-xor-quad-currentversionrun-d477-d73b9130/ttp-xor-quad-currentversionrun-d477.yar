rule TTP_XOR_QUAD_CurrentVersionRun_d477 {
  strings:
    $key_d477 = { 87 18 [2] a3 16 [2] 88 3a [2] a6 18 [2] b2 03 [2] bd 19 [2] a3 04 [2] a1 05 [2] ba 03 [2] a6 04 [2] ba 2b }

  condition:
    any of them
}