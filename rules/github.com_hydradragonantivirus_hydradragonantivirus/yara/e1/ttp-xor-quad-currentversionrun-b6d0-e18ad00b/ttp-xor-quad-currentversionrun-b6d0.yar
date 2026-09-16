rule TTP_XOR_QUAD_CurrentVersionRun_b6d0 {
  strings:
    $key_b6d0 = { e5 bf [2] c1 b1 [2] ea 9d [2] c4 bf [2] d0 a4 [2] df be [2] c1 a3 [2] c3 a2 [2] d8 a4 [2] c4 a3 [2] d8 8c }

  condition:
    any of them
}