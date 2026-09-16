rule TTP_XOR_QUAD_CurrentVersionRun_6342 {
  strings:
    $key_6342 = { 30 2d [2] 14 23 [2] 3f 0f [2] 11 2d [2] 05 36 [2] 0a 2c [2] 14 31 [2] 16 30 [2] 0d 36 [2] 11 31 [2] 0d 1e }

  condition:
    any of them
}