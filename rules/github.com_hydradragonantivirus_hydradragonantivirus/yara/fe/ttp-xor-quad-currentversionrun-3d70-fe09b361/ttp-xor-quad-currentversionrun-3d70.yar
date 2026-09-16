rule TTP_XOR_QUAD_CurrentVersionRun_3d70 {
  strings:
    $key_3d70 = { 6e 1f [2] 4a 11 [2] 61 3d [2] 4f 1f [2] 5b 04 [2] 54 1e [2] 4a 03 [2] 48 02 [2] 53 04 [2] 4f 03 [2] 53 2c }

  condition:
    any of them
}