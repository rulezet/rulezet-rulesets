rule TTP_XOR_QUAD_CurrentVersionRun_c808 {
  strings:
    $key_c808 = { 9b 67 [2] bf 69 [2] 94 45 [2] ba 67 [2] ae 7c [2] a1 66 [2] bf 7b [2] bd 7a [2] a6 7c [2] ba 7b [2] a6 54 }

  condition:
    any of them
}