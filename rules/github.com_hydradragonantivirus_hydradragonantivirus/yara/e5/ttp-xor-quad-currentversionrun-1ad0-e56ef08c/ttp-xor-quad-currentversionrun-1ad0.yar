rule TTP_XOR_QUAD_CurrentVersionRun_1ad0 {
  strings:
    $key_1ad0 = { 49 bf [2] 6d b1 [2] 46 9d [2] 68 bf [2] 7c a4 [2] 73 be [2] 6d a3 [2] 6f a2 [2] 74 a4 [2] 68 a3 [2] 74 8c }

  condition:
    any of them
}