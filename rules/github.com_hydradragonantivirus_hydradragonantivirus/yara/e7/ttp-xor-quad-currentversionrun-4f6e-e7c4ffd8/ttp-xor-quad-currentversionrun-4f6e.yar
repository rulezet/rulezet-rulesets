rule TTP_XOR_QUAD_CurrentVersionRun_4f6e {
  strings:
    $key_4f6e = { 1c 01 [2] 38 0f [2] 13 23 [2] 3d 01 [2] 29 1a [2] 26 00 [2] 38 1d [2] 3a 1c [2] 21 1a [2] 3d 1d [2] 21 32 }

  condition:
    any of them
}