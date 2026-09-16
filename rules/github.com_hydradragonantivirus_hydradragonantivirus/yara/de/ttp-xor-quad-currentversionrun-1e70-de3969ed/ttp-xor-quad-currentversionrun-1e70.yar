rule TTP_XOR_QUAD_CurrentVersionRun_1e70 {
  strings:
    $key_1e70 = { 4d 1f [2] 69 11 [2] 42 3d [2] 6c 1f [2] 78 04 [2] 77 1e [2] 69 03 [2] 6b 02 [2] 70 04 [2] 6c 03 [2] 70 2c }

  condition:
    any of them
}