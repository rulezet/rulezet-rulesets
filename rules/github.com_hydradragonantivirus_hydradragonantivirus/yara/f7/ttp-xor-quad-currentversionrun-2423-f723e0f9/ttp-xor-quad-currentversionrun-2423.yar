rule TTP_XOR_QUAD_CurrentVersionRun_2423 {
  strings:
    $key_2423 = { 77 4c [2] 53 42 [2] 78 6e [2] 56 4c [2] 42 57 [2] 4d 4d [2] 53 50 [2] 51 51 [2] 4a 57 [2] 56 50 [2] 4a 7f }

  condition:
    any of them
}