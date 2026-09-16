rule TTP_XOR_QUAD_CurrentVersionRun_2170 {
  strings:
    $key_2170 = { 72 1f [2] 56 11 [2] 7d 3d [2] 53 1f [2] 47 04 [2] 48 1e [2] 56 03 [2] 54 02 [2] 4f 04 [2] 53 03 [2] 4f 2c }

  condition:
    any of them
}