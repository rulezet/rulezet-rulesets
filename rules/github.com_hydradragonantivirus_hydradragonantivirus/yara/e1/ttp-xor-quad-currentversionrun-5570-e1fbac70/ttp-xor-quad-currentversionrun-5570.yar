rule TTP_XOR_QUAD_CurrentVersionRun_5570 {
  strings:
    $key_5570 = { 06 1f [2] 22 11 [2] 09 3d [2] 27 1f [2] 33 04 [2] 3c 1e [2] 22 03 [2] 20 02 [2] 3b 04 [2] 27 03 [2] 3b 2c }

  condition:
    any of them
}