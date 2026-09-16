rule TTP_XOR_QUAD_CurrentVersionRun_3323 {
  strings:
    $key_3323 = { 60 4c [2] 44 42 [2] 6f 6e [2] 41 4c [2] 55 57 [2] 5a 4d [2] 44 50 [2] 46 51 [2] 5d 57 [2] 41 50 [2] 5d 7f }

  condition:
    any of them
}