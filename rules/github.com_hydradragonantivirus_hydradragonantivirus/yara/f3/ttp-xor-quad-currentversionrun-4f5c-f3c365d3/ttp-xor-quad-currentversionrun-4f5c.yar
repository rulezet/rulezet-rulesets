rule TTP_XOR_QUAD_CurrentVersionRun_4f5c {
  strings:
    $key_4f5c = { 1c 33 [2] 38 3d [2] 13 11 [2] 3d 33 [2] 29 28 [2] 26 32 [2] 38 2f [2] 3a 2e [2] 21 28 [2] 3d 2f [2] 21 00 }

  condition:
    any of them
}