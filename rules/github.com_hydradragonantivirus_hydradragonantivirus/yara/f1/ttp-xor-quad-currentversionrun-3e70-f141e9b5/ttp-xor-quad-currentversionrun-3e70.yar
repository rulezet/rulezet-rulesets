rule TTP_XOR_QUAD_CurrentVersionRun_3e70 {
  strings:
    $key_3e70 = { 6d 1f [2] 49 11 [2] 62 3d [2] 4c 1f [2] 58 04 [2] 57 1e [2] 49 03 [2] 4b 02 [2] 50 04 [2] 4c 03 [2] 50 2c }

  condition:
    any of them
}