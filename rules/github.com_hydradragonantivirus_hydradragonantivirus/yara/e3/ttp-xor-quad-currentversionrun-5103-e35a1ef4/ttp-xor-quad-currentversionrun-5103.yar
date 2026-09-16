rule TTP_XOR_QUAD_CurrentVersionRun_5103 {
  strings:
    $key_5103 = { 02 6c [2] 26 62 [2] 0d 4e [2] 23 6c [2] 37 77 [2] 38 6d [2] 26 70 [2] 24 71 [2] 3f 77 [2] 23 70 [2] 3f 5f }

  condition:
    any of them
}