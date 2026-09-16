rule TTP_XOR_QUAD_CurrentVersionRun_4642 {
  strings:
    $key_4642 = { 15 2d [2] 31 23 [2] 1a 0f [2] 34 2d [2] 20 36 [2] 2f 2c [2] 31 31 [2] 33 30 [2] 28 36 [2] 34 31 [2] 28 1e }

  condition:
    any of them
}