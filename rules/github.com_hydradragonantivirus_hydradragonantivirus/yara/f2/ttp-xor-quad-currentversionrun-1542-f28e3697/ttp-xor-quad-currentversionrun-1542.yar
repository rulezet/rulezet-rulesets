rule TTP_XOR_QUAD_CurrentVersionRun_1542 {
  strings:
    $key_1542 = { 46 2d [2] 62 23 [2] 49 0f [2] 67 2d [2] 73 36 [2] 7c 2c [2] 62 31 [2] 60 30 [2] 7b 36 [2] 67 31 [2] 7b 1e }

  condition:
    any of them
}