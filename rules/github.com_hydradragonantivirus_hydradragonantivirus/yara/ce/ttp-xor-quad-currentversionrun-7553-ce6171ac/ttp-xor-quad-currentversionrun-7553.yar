rule TTP_XOR_QUAD_CurrentVersionRun_7553 {
  strings:
    $key_7553 = { 26 3c [2] 02 32 [2] 29 1e [2] 07 3c [2] 13 27 [2] 1c 3d [2] 02 20 [2] 00 21 [2] 1b 27 [2] 07 20 [2] 1b 0f }

  condition:
    any of them
}