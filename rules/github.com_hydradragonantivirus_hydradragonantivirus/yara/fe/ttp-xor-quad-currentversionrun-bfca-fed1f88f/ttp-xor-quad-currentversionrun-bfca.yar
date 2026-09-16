rule TTP_XOR_QUAD_CurrentVersionRun_bfca {
  strings:
    $key_bfca = { ec a5 [2] c8 ab [2] e3 87 [2] cd a5 [2] d9 be [2] d6 a4 [2] c8 b9 [2] ca b8 [2] d1 be [2] cd b9 [2] d1 96 }

  condition:
    any of them
}