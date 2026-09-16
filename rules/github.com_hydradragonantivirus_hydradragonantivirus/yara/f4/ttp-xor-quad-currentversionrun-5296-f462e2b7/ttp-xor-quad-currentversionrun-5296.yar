rule TTP_XOR_QUAD_CurrentVersionRun_5296 {
  strings:
    $key_5296 = { 01 f9 [2] 25 f7 [2] 0e db [2] 20 f9 [2] 34 e2 [2] 3b f8 [2] 25 e5 [2] 27 e4 [2] 3c e2 [2] 20 e5 [2] 3c ca }

  condition:
    any of them
}