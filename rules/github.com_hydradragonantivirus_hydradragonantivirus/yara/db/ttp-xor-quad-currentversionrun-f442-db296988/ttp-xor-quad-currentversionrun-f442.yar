rule TTP_XOR_QUAD_CurrentVersionRun_f442 {
  strings:
    $key_f442 = { a7 2d [2] 83 23 [2] a8 0f [2] 86 2d [2] 92 36 [2] 9d 2c [2] 83 31 [2] 81 30 [2] 9a 36 [2] 86 31 [2] 9a 1e }

  condition:
    any of them
}