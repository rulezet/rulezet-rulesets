rule TTP_XOR_QUAD_CurrentVersionRun_2270 {
  strings:
    $key_2270 = { 71 1f [2] 55 11 [2] 7e 3d [2] 50 1f [2] 44 04 [2] 4b 1e [2] 55 03 [2] 57 02 [2] 4c 04 [2] 50 03 [2] 4c 2c }

  condition:
    any of them
}