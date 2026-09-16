rule TTP_XOR_QUAD_CurrentVersionRun_6842 {
  strings:
    $key_6842 = { 3b 2d [2] 1f 23 [2] 34 0f [2] 1a 2d [2] 0e 36 [2] 01 2c [2] 1f 31 [2] 1d 30 [2] 06 36 [2] 1a 31 [2] 06 1e }

  condition:
    any of them
}