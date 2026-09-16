rule TTP_XOR_QUAD_CurrentVersionRun_1370 {
  strings:
    $key_1370 = { 40 1f [2] 64 11 [2] 4f 3d [2] 61 1f [2] 75 04 [2] 7a 1e [2] 64 03 [2] 66 02 [2] 7d 04 [2] 61 03 [2] 7d 2c }

  condition:
    any of them
}