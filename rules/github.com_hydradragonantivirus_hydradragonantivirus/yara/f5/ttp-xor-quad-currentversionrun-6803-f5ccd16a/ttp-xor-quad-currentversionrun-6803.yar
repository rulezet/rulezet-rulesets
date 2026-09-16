rule TTP_XOR_QUAD_CurrentVersionRun_6803 {
  strings:
    $key_6803 = { 3b 6c [2] 1f 62 [2] 34 4e [2] 1a 6c [2] 0e 77 [2] 01 6d [2] 1f 70 [2] 1d 71 [2] 06 77 [2] 1a 70 [2] 06 5f }

  condition:
    any of them
}