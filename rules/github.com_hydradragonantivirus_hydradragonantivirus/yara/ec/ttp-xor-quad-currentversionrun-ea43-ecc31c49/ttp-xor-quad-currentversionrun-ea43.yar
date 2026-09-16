rule TTP_XOR_QUAD_CurrentVersionRun_ea43 {
  strings:
    $key_ea43 = { b9 2c [2] 9d 22 [2] b6 0e [2] 98 2c [2] 8c 37 [2] 83 2d [2] 9d 30 [2] 9f 31 [2] 84 37 [2] 98 30 [2] 84 1f }

  condition:
    any of them
}