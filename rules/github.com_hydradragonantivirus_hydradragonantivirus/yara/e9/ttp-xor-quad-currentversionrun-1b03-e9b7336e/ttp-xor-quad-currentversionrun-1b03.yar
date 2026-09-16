rule TTP_XOR_QUAD_CurrentVersionRun_1b03 {
  strings:
    $key_1b03 = { 48 6c [2] 6c 62 [2] 47 4e [2] 69 6c [2] 7d 77 [2] 72 6d [2] 6c 70 [2] 6e 71 [2] 75 77 [2] 69 70 [2] 75 5f }

  condition:
    any of them
}