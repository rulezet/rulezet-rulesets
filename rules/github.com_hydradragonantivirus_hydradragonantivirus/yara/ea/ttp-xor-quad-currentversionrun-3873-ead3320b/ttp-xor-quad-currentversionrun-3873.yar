rule TTP_XOR_QUAD_CurrentVersionRun_3873 {
  strings:
    $key_3873 = { 6b 1c [2] 4f 12 [2] 64 3e [2] 4a 1c [2] 5e 07 [2] 51 1d [2] 4f 00 [2] 4d 01 [2] 56 07 [2] 4a 00 [2] 56 2f }

  condition:
    any of them
}