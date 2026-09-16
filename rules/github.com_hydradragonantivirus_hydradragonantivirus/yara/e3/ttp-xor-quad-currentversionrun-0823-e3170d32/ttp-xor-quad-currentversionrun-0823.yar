rule TTP_XOR_QUAD_CurrentVersionRun_0823 {
  strings:
    $key_0823 = { 5b 4c [2] 7f 42 [2] 54 6e [2] 7a 4c [2] 6e 57 [2] 61 4d [2] 7f 50 [2] 7d 51 [2] 66 57 [2] 7a 50 [2] 66 7f }

  condition:
    any of them
}