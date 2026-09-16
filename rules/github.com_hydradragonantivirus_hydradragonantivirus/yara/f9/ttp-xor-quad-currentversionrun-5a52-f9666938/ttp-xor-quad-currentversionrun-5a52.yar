rule TTP_XOR_QUAD_CurrentVersionRun_5a52 {
  strings:
    $key_5a52 = { 09 3d [2] 2d 33 [2] 06 1f [2] 28 3d [2] 3c 26 [2] 33 3c [2] 2d 21 [2] 2f 20 [2] 34 26 [2] 28 21 [2] 34 0e }

  condition:
    any of them
}