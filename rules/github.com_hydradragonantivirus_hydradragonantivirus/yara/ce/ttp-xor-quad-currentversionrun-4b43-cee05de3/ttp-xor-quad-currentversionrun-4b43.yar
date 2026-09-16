rule TTP_XOR_QUAD_CurrentVersionRun_4b43 {
  strings:
    $key_4b43 = { 18 2c [2] 3c 22 [2] 17 0e [2] 39 2c [2] 2d 37 [2] 22 2d [2] 3c 30 [2] 3e 31 [2] 25 37 [2] 39 30 [2] 25 1f }

  condition:
    any of them
}