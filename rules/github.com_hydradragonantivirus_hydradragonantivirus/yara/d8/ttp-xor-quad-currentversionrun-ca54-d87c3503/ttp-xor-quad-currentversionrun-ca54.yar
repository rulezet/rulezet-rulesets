rule TTP_XOR_QUAD_CurrentVersionRun_ca54 {
  strings:
    $key_ca54 = { 99 3b [2] bd 35 [2] 96 19 [2] b8 3b [2] ac 20 [2] a3 3a [2] bd 27 [2] bf 26 [2] a4 20 [2] b8 27 [2] a4 08 }

  condition:
    any of them
}