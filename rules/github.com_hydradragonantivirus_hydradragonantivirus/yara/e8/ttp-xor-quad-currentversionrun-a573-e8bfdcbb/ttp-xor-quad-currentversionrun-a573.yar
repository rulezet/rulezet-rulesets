rule TTP_XOR_QUAD_CurrentVersionRun_a573 {
  strings:
    $key_a573 = { f6 1c [2] d2 12 [2] f9 3e [2] d7 1c [2] c3 07 [2] cc 1d [2] d2 00 [2] d0 01 [2] cb 07 [2] d7 00 [2] cb 2f }

  condition:
    any of them
}