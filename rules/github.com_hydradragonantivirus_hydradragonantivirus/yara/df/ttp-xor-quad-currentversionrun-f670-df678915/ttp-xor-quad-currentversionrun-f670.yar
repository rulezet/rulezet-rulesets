rule TTP_XOR_QUAD_CurrentVersionRun_f670 {
  strings:
    $key_f670 = { a5 1f [2] 81 11 [2] aa 3d [2] 84 1f [2] 90 04 [2] 9f 1e [2] 81 03 [2] 83 02 [2] 98 04 [2] 84 03 [2] 98 2c }

  condition:
    any of them
}