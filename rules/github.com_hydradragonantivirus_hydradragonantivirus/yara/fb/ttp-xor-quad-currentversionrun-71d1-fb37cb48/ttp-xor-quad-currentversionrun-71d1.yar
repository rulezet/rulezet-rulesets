rule TTP_XOR_QUAD_CurrentVersionRun_71d1 {
  strings:
    $key_71d1 = { 22 be [2] 06 b0 [2] 2d 9c [2] 03 be [2] 17 a5 [2] 18 bf [2] 06 a2 [2] 04 a3 [2] 1f a5 [2] 03 a2 [2] 1f 8d }

  condition:
    any of them
}