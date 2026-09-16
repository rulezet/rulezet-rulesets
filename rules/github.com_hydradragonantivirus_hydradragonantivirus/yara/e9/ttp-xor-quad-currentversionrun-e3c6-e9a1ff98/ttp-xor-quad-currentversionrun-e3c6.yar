rule TTP_XOR_QUAD_CurrentVersionRun_e3c6 {
  strings:
    $key_e3c6 = { b0 a9 [2] 94 a7 [2] bf 8b [2] 91 a9 [2] 85 b2 [2] 8a a8 [2] 94 b5 [2] 96 b4 [2] 8d b2 [2] 91 b5 [2] 8d 9a }

  condition:
    any of them
}