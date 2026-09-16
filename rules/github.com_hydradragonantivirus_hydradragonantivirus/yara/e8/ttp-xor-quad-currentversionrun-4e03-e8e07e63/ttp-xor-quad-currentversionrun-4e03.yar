rule TTP_XOR_QUAD_CurrentVersionRun_4e03 {
  strings:
    $key_4e03 = { 1d 6c [2] 39 62 [2] 12 4e [2] 3c 6c [2] 28 77 [2] 27 6d [2] 39 70 [2] 3b 71 [2] 20 77 [2] 3c 70 [2] 20 5f }

  condition:
    any of them
}