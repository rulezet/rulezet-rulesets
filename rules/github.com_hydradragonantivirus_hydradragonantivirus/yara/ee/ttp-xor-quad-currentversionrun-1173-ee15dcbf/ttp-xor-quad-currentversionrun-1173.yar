rule TTP_XOR_QUAD_CurrentVersionRun_1173 {
  strings:
    $key_1173 = { 42 1c [2] 66 12 [2] 4d 3e [2] 63 1c [2] 77 07 [2] 78 1d [2] 66 00 [2] 64 01 [2] 7f 07 [2] 63 00 [2] 7f 2f }

  condition:
    any of them
}