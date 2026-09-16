rule TTP_XOR_QUAD_CurrentVersionRun_3a73 {
  strings:
    $key_3a73 = { 69 1c [2] 4d 12 [2] 66 3e [2] 48 1c [2] 5c 07 [2] 53 1d [2] 4d 00 [2] 4f 01 [2] 54 07 [2] 48 00 [2] 54 2f }

  condition:
    any of them
}