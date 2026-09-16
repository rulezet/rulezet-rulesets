rule TTP_XOR_QUAD_CurrentVersionRun_5d70 {
  strings:
    $key_5d70 = { 0e 1f [2] 2a 11 [2] 01 3d [2] 2f 1f [2] 3b 04 [2] 34 1e [2] 2a 03 [2] 28 02 [2] 33 04 [2] 2f 03 [2] 33 2c }

  condition:
    any of them
}