rule TTP_XOR_QUAD_CurrentVersionRun_fb46 {
  strings:
    $key_fb46 = { a8 29 [2] 8c 27 [2] a7 0b [2] 89 29 [2] 9d 32 [2] 92 28 [2] 8c 35 [2] 8e 34 [2] 95 32 [2] 89 35 [2] 95 1a }

  condition:
    any of them
}