rule TTP_XOR_QUAD_CurrentVersionRun_4373 {
  strings:
    $key_4373 = { 10 1c [2] 34 12 [2] 1f 3e [2] 31 1c [2] 25 07 [2] 2a 1d [2] 34 00 [2] 36 01 [2] 2d 07 [2] 31 00 [2] 2d 2f }

  condition:
    any of them
}