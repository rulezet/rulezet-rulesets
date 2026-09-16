rule TTP_XOR_QUAD_CurrentVersionRun_0803 {
  strings:
    $key_0803 = { 5b 6c [2] 7f 62 [2] 54 4e [2] 7a 6c [2] 6e 77 [2] 61 6d [2] 7f 70 [2] 7d 71 [2] 66 77 [2] 7a 70 [2] 66 5f }

  condition:
    any of them
}