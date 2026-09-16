rule TTP_XOR_QUAD_CurrentVersionRun_ca15 {
  strings:
    $key_ca15 = { 99 7a [2] bd 74 [2] 96 58 [2] b8 7a [2] ac 61 [2] a3 7b [2] bd 66 [2] bf 67 [2] a4 61 [2] b8 66 [2] a4 49 }

  condition:
    any of them
}