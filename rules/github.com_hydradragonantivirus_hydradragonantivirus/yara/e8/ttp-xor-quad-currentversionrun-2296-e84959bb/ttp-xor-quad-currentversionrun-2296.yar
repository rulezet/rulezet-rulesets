rule TTP_XOR_QUAD_CurrentVersionRun_2296 {
  strings:
    $key_2296 = { 71 f9 [2] 55 f7 [2] 7e db [2] 50 f9 [2] 44 e2 [2] 4b f8 [2] 55 e5 [2] 57 e4 [2] 4c e2 [2] 50 e5 [2] 4c ca }

  condition:
    any of them
}