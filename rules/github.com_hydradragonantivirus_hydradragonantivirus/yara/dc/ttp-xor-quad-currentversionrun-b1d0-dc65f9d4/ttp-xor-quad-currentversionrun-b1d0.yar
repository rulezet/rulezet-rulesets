rule TTP_XOR_QUAD_CurrentVersionRun_b1d0 {
  strings:
    $key_b1d0 = { e2 bf [2] c6 b1 [2] ed 9d [2] c3 bf [2] d7 a4 [2] d8 be [2] c6 a3 [2] c4 a2 [2] df a4 [2] c3 a3 [2] df 8c }

  condition:
    any of them
}