rule TTP_XOR_QUAD_CurrentVersionRun_cf54 {
  strings:
    $key_cf54 = { 9c 3b [2] b8 35 [2] 93 19 [2] bd 3b [2] a9 20 [2] a6 3a [2] b8 27 [2] ba 26 [2] a1 20 [2] bd 27 [2] a1 08 }

  condition:
    any of them
}