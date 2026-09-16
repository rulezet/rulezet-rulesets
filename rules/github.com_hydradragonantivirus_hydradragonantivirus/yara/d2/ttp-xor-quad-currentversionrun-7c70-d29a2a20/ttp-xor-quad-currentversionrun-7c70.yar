rule TTP_XOR_QUAD_CurrentVersionRun_7c70 {
  strings:
    $key_7c70 = { 2f 1f [2] 0b 11 [2] 20 3d [2] 0e 1f [2] 1a 04 [2] 15 1e [2] 0b 03 [2] 09 02 [2] 12 04 [2] 0e 03 [2] 12 2c }

  condition:
    any of them
}