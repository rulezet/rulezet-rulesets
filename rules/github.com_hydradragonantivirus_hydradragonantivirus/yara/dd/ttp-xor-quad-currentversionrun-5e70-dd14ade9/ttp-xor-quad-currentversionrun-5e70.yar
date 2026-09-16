rule TTP_XOR_QUAD_CurrentVersionRun_5e70 {
  strings:
    $key_5e70 = { 0d 1f [2] 29 11 [2] 02 3d [2] 2c 1f [2] 38 04 [2] 37 1e [2] 29 03 [2] 2b 02 [2] 30 04 [2] 2c 03 [2] 30 2c }

  condition:
    any of them
}