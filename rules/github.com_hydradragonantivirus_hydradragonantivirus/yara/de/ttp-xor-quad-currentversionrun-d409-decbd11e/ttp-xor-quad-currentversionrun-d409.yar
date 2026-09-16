rule TTP_XOR_QUAD_CurrentVersionRun_d409 {
  strings:
    $key_d409 = { 87 66 [2] a3 68 [2] 88 44 [2] a6 66 [2] b2 7d [2] bd 67 [2] a3 7a [2] a1 7b [2] ba 7d [2] a6 7a [2] ba 55 }

  condition:
    any of them
}