rule TTP_XOR_QUAD_CurrentVersionRun_0e70 {
  strings:
    $key_0e70 = { 5d 1f [2] 79 11 [2] 52 3d [2] 7c 1f [2] 68 04 [2] 67 1e [2] 79 03 [2] 7b 02 [2] 60 04 [2] 7c 03 [2] 60 2c }

  condition:
    any of them
}