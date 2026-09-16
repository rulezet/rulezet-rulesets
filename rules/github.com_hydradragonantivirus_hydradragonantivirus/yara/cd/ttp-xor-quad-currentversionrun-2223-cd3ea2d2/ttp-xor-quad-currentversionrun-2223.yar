rule TTP_XOR_QUAD_CurrentVersionRun_2223 {
  strings:
    $key_2223 = { 71 4c [2] 55 42 [2] 7e 6e [2] 50 4c [2] 44 57 [2] 4b 4d [2] 55 50 [2] 57 51 [2] 4c 57 [2] 50 50 [2] 4c 7f }

  condition:
    any of them
}