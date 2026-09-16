rule TTP_XOR_QUAD_CurrentVersionRun_fb70 {
  strings:
    $key_fb70 = { a8 1f [2] 8c 11 [2] a7 3d [2] 89 1f [2] 9d 04 [2] 92 1e [2] 8c 03 [2] 8e 02 [2] 95 04 [2] 89 03 [2] 95 2c }

  condition:
    any of them
}