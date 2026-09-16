rule TTP_XOR_QUAD_CurrentVersionRun_cff4 {
  strings:
    $key_cff4 = { 9c 9b [2] b8 95 [2] 93 b9 [2] bd 9b [2] a9 80 [2] a6 9a [2] b8 87 [2] ba 86 [2] a1 80 [2] bd 87 [2] a1 a8 }

  condition:
    any of them
}