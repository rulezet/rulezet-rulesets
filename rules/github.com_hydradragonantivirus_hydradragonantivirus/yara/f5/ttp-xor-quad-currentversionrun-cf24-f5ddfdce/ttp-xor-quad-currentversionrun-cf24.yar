rule TTP_XOR_QUAD_CurrentVersionRun_cf24 {
  strings:
    $key_cf24 = { 9c 4b [2] b8 45 [2] 93 69 [2] bd 4b [2] a9 50 [2] a6 4a [2] b8 57 [2] ba 56 [2] a1 50 [2] bd 57 [2] a1 78 }

  condition:
    any of them
}