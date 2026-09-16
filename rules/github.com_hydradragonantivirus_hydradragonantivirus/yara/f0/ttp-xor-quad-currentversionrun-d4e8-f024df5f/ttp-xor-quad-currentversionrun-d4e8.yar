rule TTP_XOR_QUAD_CurrentVersionRun_d4e8 {
  strings:
    $key_d4e8 = { 87 87 [2] a3 89 [2] 88 a5 [2] a6 87 [2] b2 9c [2] bd 86 [2] a3 9b [2] a1 9a [2] ba 9c [2] a6 9b [2] ba b4 }

  condition:
    any of them
}