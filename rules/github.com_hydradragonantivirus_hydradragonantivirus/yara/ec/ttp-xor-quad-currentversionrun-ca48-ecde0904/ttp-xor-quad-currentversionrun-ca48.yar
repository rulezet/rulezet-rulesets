rule TTP_XOR_QUAD_CurrentVersionRun_ca48 {
  strings:
    $key_ca48 = { 99 27 [2] bd 29 [2] 96 05 [2] b8 27 [2] ac 3c [2] a3 26 [2] bd 3b [2] bf 3a [2] a4 3c [2] b8 3b [2] a4 14 }

  condition:
    any of them
}