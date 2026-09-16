rule TTP_XOR_QUAD_CurrentVersionRun_ca39 {
  strings:
    $key_ca39 = { 99 56 [2] bd 58 [2] 96 74 [2] b8 56 [2] ac 4d [2] a3 57 [2] bd 4a [2] bf 4b [2] a4 4d [2] b8 4a [2] a4 65 }

  condition:
    any of them
}