rule TTP_XOR_QUAD_CurrentVersionRun_fb42 {
  strings:
    $key_fb42 = { a8 2d [2] 8c 23 [2] a7 0f [2] 89 2d [2] 9d 36 [2] 92 2c [2] 8c 31 [2] 8e 30 [2] 95 36 [2] 89 31 [2] 95 1e }

  condition:
    any of them
}