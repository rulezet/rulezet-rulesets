rule TTP_XOR_QUAD_CurrentVersionRun_2803 {
  strings:
    $key_2803 = { 7b 6c [2] 5f 62 [2] 74 4e [2] 5a 6c [2] 4e 77 [2] 41 6d [2] 5f 70 [2] 5d 71 [2] 46 77 [2] 5a 70 [2] 46 5f }

  condition:
    any of them
}