rule TTP_XOR_QUAD_CurrentVersionRun_ecee {
  strings:
    $key_ecee = { bf 81 [2] 9b 8f [2] b0 a3 [2] 9e 81 [2] 8a 9a [2] 85 80 [2] 9b 9d [2] 99 9c [2] 82 9a [2] 9e 9d [2] 82 b2 }

  condition:
    any of them
}