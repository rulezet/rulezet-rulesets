rule TTP_XOR_QUAD_CurrentVersionRun_60d1 {
  strings:
    $key_60d1 = { 33 be [2] 17 b0 [2] 3c 9c [2] 12 be [2] 06 a5 [2] 09 bf [2] 17 a2 [2] 15 a3 [2] 0e a5 [2] 12 a2 [2] 0e 8d }

  condition:
    any of them
}