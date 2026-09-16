rule TTP_XOR_QUAD_CurrentVersionRun_1ad1 {
  strings:
    $key_1ad1 = { 49 be [2] 6d b0 [2] 46 9c [2] 68 be [2] 7c a5 [2] 73 bf [2] 6d a2 [2] 6f a3 [2] 74 a5 [2] 68 a2 [2] 74 8d }

  condition:
    any of them
}