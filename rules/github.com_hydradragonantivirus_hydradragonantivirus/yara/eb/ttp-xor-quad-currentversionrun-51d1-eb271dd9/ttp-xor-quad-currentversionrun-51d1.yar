rule TTP_XOR_QUAD_CurrentVersionRun_51d1 {
  strings:
    $key_51d1 = { 02 be [2] 26 b0 [2] 0d 9c [2] 23 be [2] 37 a5 [2] 38 bf [2] 26 a2 [2] 24 a3 [2] 3f a5 [2] 23 a2 [2] 3f 8d }

  condition:
    any of them
}