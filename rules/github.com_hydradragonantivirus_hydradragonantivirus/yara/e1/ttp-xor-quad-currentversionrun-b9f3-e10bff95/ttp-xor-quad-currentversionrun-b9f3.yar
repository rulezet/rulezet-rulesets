rule TTP_XOR_QUAD_CurrentVersionRun_b9f3 {
  strings:
    $key_b9f3 = { ea 9c [2] ce 92 [2] e5 be [2] cb 9c [2] df 87 [2] d0 9d [2] ce 80 [2] cc 81 [2] d7 87 [2] cb 80 [2] d7 af }

  condition:
    any of them
}