rule TTP_XOR_QUAD_CurrentVersionRun_a3f3 {
  strings:
    $key_a3f3 = { f0 9c [2] d4 92 [2] ff be [2] d1 9c [2] c5 87 [2] ca 9d [2] d4 80 [2] d6 81 [2] cd 87 [2] d1 80 [2] cd af }

  condition:
    any of them
}