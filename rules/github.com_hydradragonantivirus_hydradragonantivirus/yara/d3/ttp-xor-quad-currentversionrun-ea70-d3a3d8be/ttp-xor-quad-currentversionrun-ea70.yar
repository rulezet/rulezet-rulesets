rule TTP_XOR_QUAD_CurrentVersionRun_ea70 {
  strings:
    $key_ea70 = { b9 1f [2] 9d 11 [2] b6 3d [2] 98 1f [2] 8c 04 [2] 83 1e [2] 9d 03 [2] 9f 02 [2] 84 04 [2] 98 03 [2] 84 2c }

  condition:
    any of them
}