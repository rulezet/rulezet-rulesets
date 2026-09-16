rule TTP_XOR_QUAD_CurrentVersionRun_ca19 {
  strings:
    $key_ca19 = { 99 76 [2] bd 78 [2] 96 54 [2] b8 76 [2] ac 6d [2] a3 77 [2] bd 6a [2] bf 6b [2] a4 6d [2] b8 6a [2] a4 45 }

  condition:
    any of them
}