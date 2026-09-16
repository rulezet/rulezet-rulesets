rule TTP_XOR_QUAD_CurrentVersionRun_e870 {
  strings:
    $key_e870 = { bb 1f [2] 9f 11 [2] b4 3d [2] 9a 1f [2] 8e 04 [2] 81 1e [2] 9f 03 [2] 9d 02 [2] 86 04 [2] 9a 03 [2] 86 2c }

  condition:
    any of them
}