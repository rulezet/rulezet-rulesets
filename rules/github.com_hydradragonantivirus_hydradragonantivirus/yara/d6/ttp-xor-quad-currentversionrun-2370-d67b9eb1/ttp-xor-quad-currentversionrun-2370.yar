rule TTP_XOR_QUAD_CurrentVersionRun_2370 {
  strings:
    $key_2370 = { 70 1f [2] 54 11 [2] 7f 3d [2] 51 1f [2] 45 04 [2] 4a 1e [2] 54 03 [2] 56 02 [2] 4d 04 [2] 51 03 [2] 4d 2c }

  condition:
    any of them
}