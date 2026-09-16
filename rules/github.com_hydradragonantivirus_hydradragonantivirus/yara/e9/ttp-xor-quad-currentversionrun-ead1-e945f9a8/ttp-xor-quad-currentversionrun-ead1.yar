rule TTP_XOR_QUAD_CurrentVersionRun_ead1 {
  strings:
    $key_ead1 = { b9 be [2] 9d b0 [2] b6 9c [2] 98 be [2] 8c a5 [2] 83 bf [2] 9d a2 [2] 9f a3 [2] 84 a5 [2] 98 a2 [2] 84 8d }

  condition:
    any of them
}