rule TTP_XOR_QUAD_CurrentVersionRun_d357 {
  strings:
    $key_d357 = { 80 38 [2] a4 36 [2] 8f 1a [2] a1 38 [2] b5 23 [2] ba 39 [2] a4 24 [2] a6 25 [2] bd 23 [2] a1 24 [2] bd 0b }

  condition:
    any of them
}