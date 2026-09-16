rule TTP_XOR_QUAD_CurrentVersionRun_ca45 {
  strings:
    $key_ca45 = { 99 2a [2] bd 24 [2] 96 08 [2] b8 2a [2] ac 31 [2] a3 2b [2] bd 36 [2] bf 37 [2] a4 31 [2] b8 36 [2] a4 19 }

  condition:
    any of them
}