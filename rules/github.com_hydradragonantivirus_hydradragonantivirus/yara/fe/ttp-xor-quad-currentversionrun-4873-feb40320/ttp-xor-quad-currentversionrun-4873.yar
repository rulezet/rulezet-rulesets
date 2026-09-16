rule TTP_XOR_QUAD_CurrentVersionRun_4873 {
  strings:
    $key_4873 = { 1b 1c [2] 3f 12 [2] 14 3e [2] 3a 1c [2] 2e 07 [2] 21 1d [2] 3f 00 [2] 3d 01 [2] 26 07 [2] 3a 00 [2] 26 2f }

  condition:
    any of them
}