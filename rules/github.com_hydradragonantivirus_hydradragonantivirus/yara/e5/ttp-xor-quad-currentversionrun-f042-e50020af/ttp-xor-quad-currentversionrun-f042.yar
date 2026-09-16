rule TTP_XOR_QUAD_CurrentVersionRun_f042 {
  strings:
    $key_f042 = { a3 2d [2] 87 23 [2] ac 0f [2] 82 2d [2] 96 36 [2] 99 2c [2] 87 31 [2] 85 30 [2] 9e 36 [2] 82 31 [2] 9e 1e }

  condition:
    any of them
}