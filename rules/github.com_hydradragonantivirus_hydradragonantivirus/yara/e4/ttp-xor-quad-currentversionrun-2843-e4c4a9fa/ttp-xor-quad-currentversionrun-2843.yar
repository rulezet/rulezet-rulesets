rule TTP_XOR_QUAD_CurrentVersionRun_2843 {
  strings:
    $key_2843 = { 7b 2c [2] 5f 22 [2] 74 0e [2] 5a 2c [2] 4e 37 [2] 41 2d [2] 5f 30 [2] 5d 31 [2] 46 37 [2] 5a 30 [2] 46 1f }

  condition:
    any of them
}