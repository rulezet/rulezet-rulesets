rule TTP_XOR_QUAD_CurrentVersionRun_4a42 {
  strings:
    $key_4a42 = { 19 2d [2] 3d 23 [2] 16 0f [2] 38 2d [2] 2c 36 [2] 23 2c [2] 3d 31 [2] 3f 30 [2] 24 36 [2] 38 31 [2] 24 1e }

  condition:
    any of them
}