rule TTP_XOR_QUAD_CurrentVersionRun_4d03 {
  strings:
    $key_4d03 = { 1e 6c [2] 3a 62 [2] 11 4e [2] 3f 6c [2] 2b 77 [2] 24 6d [2] 3a 70 [2] 38 71 [2] 23 77 [2] 3f 70 [2] 23 5f }

  condition:
    any of them
}