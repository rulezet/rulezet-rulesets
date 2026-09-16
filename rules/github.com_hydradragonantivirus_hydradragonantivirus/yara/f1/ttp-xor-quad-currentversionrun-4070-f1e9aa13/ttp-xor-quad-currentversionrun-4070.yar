rule TTP_XOR_QUAD_CurrentVersionRun_4070 {
  strings:
    $key_4070 = { 13 1f [2] 37 11 [2] 1c 3d [2] 32 1f [2] 26 04 [2] 29 1e [2] 37 03 [2] 35 02 [2] 2e 04 [2] 32 03 [2] 2e 2c }

  condition:
    any of them
}