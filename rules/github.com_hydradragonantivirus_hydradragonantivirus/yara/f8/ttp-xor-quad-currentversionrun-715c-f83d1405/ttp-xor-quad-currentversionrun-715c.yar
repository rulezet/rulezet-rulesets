rule TTP_XOR_QUAD_CurrentVersionRun_715c {
  strings:
    $key_715c = { 22 33 [2] 06 3d [2] 2d 11 [2] 03 33 [2] 17 28 [2] 18 32 [2] 06 2f [2] 04 2e [2] 1f 28 [2] 03 2f [2] 1f 00 }

  condition:
    any of them
}