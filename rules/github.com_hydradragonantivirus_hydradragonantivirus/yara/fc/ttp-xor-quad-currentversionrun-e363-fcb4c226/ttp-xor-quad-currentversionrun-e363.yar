rule TTP_XOR_QUAD_CurrentVersionRun_e363 {
  strings:
    $key_e363 = { b0 0c [2] 94 02 [2] bf 2e [2] 91 0c [2] 85 17 [2] 8a 0d [2] 94 10 [2] 96 11 [2] 8d 17 [2] 91 10 [2] 8d 3f }

  condition:
    any of them
}