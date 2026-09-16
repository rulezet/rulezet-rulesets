rule TTP_XOR_QUAD_CurrentVersionRun_d4e4 {
  strings:
    $key_d4e4 = { 87 8b [2] a3 85 [2] 88 a9 [2] a6 8b [2] b2 90 [2] bd 8a [2] a3 97 [2] a1 96 [2] ba 90 [2] a6 97 [2] ba b8 }

  condition:
    any of them
}