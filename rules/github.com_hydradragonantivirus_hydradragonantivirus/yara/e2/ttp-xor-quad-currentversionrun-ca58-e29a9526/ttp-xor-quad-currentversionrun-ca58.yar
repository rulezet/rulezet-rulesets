rule TTP_XOR_QUAD_CurrentVersionRun_ca58 {
  strings:
    $key_ca58 = { 99 37 [2] bd 39 [2] 96 15 [2] b8 37 [2] ac 2c [2] a3 36 [2] bd 2b [2] bf 2a [2] a4 2c [2] b8 2b [2] a4 04 }

  condition:
    any of them
}