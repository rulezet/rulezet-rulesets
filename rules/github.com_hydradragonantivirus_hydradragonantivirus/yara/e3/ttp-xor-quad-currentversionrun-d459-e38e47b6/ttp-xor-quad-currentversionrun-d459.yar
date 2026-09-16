rule TTP_XOR_QUAD_CurrentVersionRun_d459 {
  strings:
    $key_d459 = { 87 36 [2] a3 38 [2] 88 14 [2] a6 36 [2] b2 2d [2] bd 37 [2] a3 2a [2] a1 2b [2] ba 2d [2] a6 2a [2] ba 05 }

  condition:
    any of them
}