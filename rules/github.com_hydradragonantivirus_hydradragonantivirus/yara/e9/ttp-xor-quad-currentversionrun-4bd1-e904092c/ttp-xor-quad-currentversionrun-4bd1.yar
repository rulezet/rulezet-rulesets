rule TTP_XOR_QUAD_CurrentVersionRun_4bd1 {
  strings:
    $key_4bd1 = { 18 be [2] 3c b0 [2] 17 9c [2] 39 be [2] 2d a5 [2] 22 bf [2] 3c a2 [2] 3e a3 [2] 25 a5 [2] 39 a2 [2] 25 8d }

  condition:
    any of them
}