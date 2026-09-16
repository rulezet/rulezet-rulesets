rule TTP_XOR_QUAD_CurrentVersionRun_6542 {
  strings:
    $key_6542 = { 36 2d [2] 12 23 [2] 39 0f [2] 17 2d [2] 03 36 [2] 0c 2c [2] 12 31 [2] 10 30 [2] 0b 36 [2] 17 31 [2] 0b 1e }

  condition:
    any of them
}