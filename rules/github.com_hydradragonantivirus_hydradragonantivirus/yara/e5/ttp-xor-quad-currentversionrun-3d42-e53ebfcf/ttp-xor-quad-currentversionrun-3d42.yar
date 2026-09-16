rule TTP_XOR_QUAD_CurrentVersionRun_3d42 {
  strings:
    $key_3d42 = { 6e 2d [2] 4a 23 [2] 61 0f [2] 4f 2d [2] 5b 36 [2] 54 2c [2] 4a 31 [2] 48 30 [2] 53 36 [2] 4f 31 [2] 53 1e }

  condition:
    any of them
}