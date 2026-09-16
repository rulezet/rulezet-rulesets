rule TTP_XOR_QUAD_CurrentVersionRun_cf79 {
  strings:
    $key_cf79 = { 9c 16 [2] b8 18 [2] 93 34 [2] bd 16 [2] a9 0d [2] a6 17 [2] b8 0a [2] ba 0b [2] a1 0d [2] bd 0a [2] a1 25 }

  condition:
    any of them
}