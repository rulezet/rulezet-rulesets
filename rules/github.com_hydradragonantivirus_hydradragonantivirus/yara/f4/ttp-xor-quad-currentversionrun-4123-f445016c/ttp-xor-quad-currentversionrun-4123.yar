rule TTP_XOR_QUAD_CurrentVersionRun_4123 {
  strings:
    $key_4123 = { 12 4c [2] 36 42 [2] 1d 6e [2] 33 4c [2] 27 57 [2] 28 4d [2] 36 50 [2] 34 51 [2] 2f 57 [2] 33 50 [2] 2f 7f }

  condition:
    any of them
}