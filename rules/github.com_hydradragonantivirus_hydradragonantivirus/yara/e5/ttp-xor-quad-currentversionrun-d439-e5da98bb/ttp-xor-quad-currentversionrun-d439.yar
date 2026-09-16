rule TTP_XOR_QUAD_CurrentVersionRun_d439 {
  strings:
    $key_d439 = { 87 56 [2] a3 58 [2] 88 74 [2] a6 56 [2] b2 4d [2] bd 57 [2] a3 4a [2] a1 4b [2] ba 4d [2] a6 4a [2] ba 65 }

  condition:
    any of them
}