rule TTP_XOR_QUAD_CurrentVersionRun_0770 {
  strings:
    $key_0770 = { 54 1f [2] 70 11 [2] 5b 3d [2] 75 1f [2] 61 04 [2] 6e 1e [2] 70 03 [2] 72 02 [2] 69 04 [2] 75 03 [2] 69 2c }

  condition:
    any of them
}