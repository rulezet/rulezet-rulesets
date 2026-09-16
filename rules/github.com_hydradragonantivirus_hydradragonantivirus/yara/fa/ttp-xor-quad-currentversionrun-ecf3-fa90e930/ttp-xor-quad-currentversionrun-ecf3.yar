rule TTP_XOR_QUAD_CurrentVersionRun_ecf3 {
  strings:
    $key_ecf3 = { bf 9c [2] 9b 92 [2] b0 be [2] 9e 9c [2] 8a 87 [2] 85 9d [2] 9b 80 [2] 99 81 [2] 82 87 [2] 9e 80 [2] 82 af }

  condition:
    any of them
}