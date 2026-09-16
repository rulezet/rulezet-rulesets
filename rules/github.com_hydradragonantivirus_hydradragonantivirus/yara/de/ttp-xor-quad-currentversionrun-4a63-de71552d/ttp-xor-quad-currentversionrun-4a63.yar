rule TTP_XOR_QUAD_CurrentVersionRun_4a63 {
  strings:
    $key_4a63 = { 19 0c [2] 3d 02 [2] 16 2e [2] 38 0c [2] 2c 17 [2] 23 0d [2] 3d 10 [2] 3f 11 [2] 24 17 [2] 38 10 [2] 24 3f }

  condition:
    any of them
}