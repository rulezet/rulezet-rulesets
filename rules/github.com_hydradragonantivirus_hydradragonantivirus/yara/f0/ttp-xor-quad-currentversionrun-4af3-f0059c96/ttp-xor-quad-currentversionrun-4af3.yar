rule TTP_XOR_QUAD_CurrentVersionRun_4af3 {
  strings:
    $key_4af3 = { 19 9c [2] 3d 92 [2] 16 be [2] 38 9c [2] 2c 87 [2] 23 9d [2] 3d 80 [2] 3f 81 [2] 24 87 [2] 38 80 [2] 24 af }

  condition:
    any of them
}