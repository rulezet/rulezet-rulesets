rule TTP_XOR_QUAD_CurrentVersionRun_5670 {
  strings:
    $key_5670 = { 05 1f [2] 21 11 [2] 0a 3d [2] 24 1f [2] 30 04 [2] 3f 1e [2] 21 03 [2] 23 02 [2] 38 04 [2] 24 03 [2] 38 2c }

  condition:
    any of them
}