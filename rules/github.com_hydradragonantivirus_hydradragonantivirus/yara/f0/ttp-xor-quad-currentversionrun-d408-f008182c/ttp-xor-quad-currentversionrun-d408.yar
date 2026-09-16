rule TTP_XOR_QUAD_CurrentVersionRun_d408 {
  strings:
    $key_d408 = { 87 67 [2] a3 69 [2] 88 45 [2] a6 67 [2] b2 7c [2] bd 66 [2] a3 7b [2] a1 7a [2] ba 7c [2] a6 7b [2] ba 54 }

  condition:
    any of them
}