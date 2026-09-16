rule TTP_XOR_QUAD_CurrentVersionRun_b8d7 {
  strings:
    $key_b8d7 = { eb b8 [2] cf b6 [2] e4 9a [2] ca b8 [2] de a3 [2] d1 b9 [2] cf a4 [2] cd a5 [2] d6 a3 [2] ca a4 [2] d6 8b }

  condition:
    any of them
}