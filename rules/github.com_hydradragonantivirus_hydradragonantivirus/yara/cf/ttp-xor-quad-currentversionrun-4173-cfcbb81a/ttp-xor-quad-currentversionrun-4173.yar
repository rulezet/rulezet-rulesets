rule TTP_XOR_QUAD_CurrentVersionRun_4173 {
  strings:
    $key_4173 = { 12 1c [2] 36 12 [2] 1d 3e [2] 33 1c [2] 27 07 [2] 28 1d [2] 36 00 [2] 34 01 [2] 2f 07 [2] 33 00 [2] 2f 2f }

  condition:
    any of them
}