rule TTP_XOR_QUAD_CurrentVersionRun_d415 {
  strings:
    $key_d415 = { 87 7a [2] a3 74 [2] 88 58 [2] a6 7a [2] b2 61 [2] bd 7b [2] a3 66 [2] a1 67 [2] ba 61 [2] a6 66 [2] ba 49 }

  condition:
    any of them
}