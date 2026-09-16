rule TTP_XOR_QUAD_CurrentVersionRun_6370 {
  strings:
    $key_6370 = { 30 1f [2] 14 11 [2] 3f 3d [2] 11 1f [2] 05 04 [2] 0a 1e [2] 14 03 [2] 16 02 [2] 0d 04 [2] 11 03 [2] 0d 2c }

  condition:
    any of them
}