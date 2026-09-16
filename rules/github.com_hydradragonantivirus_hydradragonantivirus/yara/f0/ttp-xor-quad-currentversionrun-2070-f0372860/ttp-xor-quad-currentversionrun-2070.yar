rule TTP_XOR_QUAD_CurrentVersionRun_2070 {
  strings:
    $key_2070 = { 73 1f [2] 57 11 [2] 7c 3d [2] 52 1f [2] 46 04 [2] 49 1e [2] 57 03 [2] 55 02 [2] 4e 04 [2] 52 03 [2] 4e 2c }

  condition:
    any of them
}