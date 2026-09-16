rule TTP_XOR_QUAD_CurrentVersionRun_3103 {
  strings:
    $key_3103 = { 62 6c [2] 46 62 [2] 6d 4e [2] 43 6c [2] 57 77 [2] 58 6d [2] 46 70 [2] 44 71 [2] 5f 77 [2] 43 70 [2] 5f 5f }

  condition:
    any of them
}