rule TTP_XOR_QUAD_CurrentVersionRun_4903 {
  strings:
    $key_4903 = { 1a 6c [2] 3e 62 [2] 15 4e [2] 3b 6c [2] 2f 77 [2] 20 6d [2] 3e 70 [2] 3c 71 [2] 27 77 [2] 3b 70 [2] 27 5f }

  condition:
    any of them
}