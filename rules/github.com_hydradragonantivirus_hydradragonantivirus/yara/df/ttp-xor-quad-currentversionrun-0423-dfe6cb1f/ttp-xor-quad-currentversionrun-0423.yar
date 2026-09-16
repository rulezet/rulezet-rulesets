rule TTP_XOR_QUAD_CurrentVersionRun_0423 {
  strings:
    $key_0423 = { 57 4c [2] 73 42 [2] 58 6e [2] 76 4c [2] 62 57 [2] 6d 4d [2] 73 50 [2] 71 51 [2] 6a 57 [2] 76 50 [2] 6a 7f }

  condition:
    any of them
}