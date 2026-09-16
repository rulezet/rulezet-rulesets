rule TTP_XOR_QUAD_CurrentVersionRun_cf59 {
  strings:
    $key_cf59 = { 9c 36 [2] b8 38 [2] 93 14 [2] bd 36 [2] a9 2d [2] a6 37 [2] b8 2a [2] ba 2b [2] a1 2d [2] bd 2a [2] a1 05 }

  condition:
    any of them
}