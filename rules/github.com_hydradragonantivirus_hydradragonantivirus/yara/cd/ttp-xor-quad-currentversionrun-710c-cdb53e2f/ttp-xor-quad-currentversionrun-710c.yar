rule TTP_XOR_QUAD_CurrentVersionRun_710c {
  strings:
    $key_710c = { 22 63 [2] 06 6d [2] 2d 41 [2] 03 63 [2] 17 78 [2] 18 62 [2] 06 7f [2] 04 7e [2] 1f 78 [2] 03 7f [2] 1f 50 }

  condition:
    any of them
}