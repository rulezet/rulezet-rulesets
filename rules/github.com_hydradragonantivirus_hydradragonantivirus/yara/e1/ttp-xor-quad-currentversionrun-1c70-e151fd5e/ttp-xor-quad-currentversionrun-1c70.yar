rule TTP_XOR_QUAD_CurrentVersionRun_1c70 {
  strings:
    $key_1c70 = { 4f 1f [2] 6b 11 [2] 40 3d [2] 6e 1f [2] 7a 04 [2] 75 1e [2] 6b 03 [2] 69 02 [2] 72 04 [2] 6e 03 [2] 72 2c }

  condition:
    any of them
}