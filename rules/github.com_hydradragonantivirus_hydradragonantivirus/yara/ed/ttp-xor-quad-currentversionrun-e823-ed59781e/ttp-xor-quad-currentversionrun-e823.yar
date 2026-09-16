rule TTP_XOR_QUAD_CurrentVersionRun_e823 {
  strings:
    $key_e823 = { bb 4c [2] 9f 42 [2] b4 6e [2] 9a 4c [2] 8e 57 [2] 81 4d [2] 9f 50 [2] 9d 51 [2] 86 57 [2] 9a 50 [2] 86 7f }

  condition:
    any of them
}