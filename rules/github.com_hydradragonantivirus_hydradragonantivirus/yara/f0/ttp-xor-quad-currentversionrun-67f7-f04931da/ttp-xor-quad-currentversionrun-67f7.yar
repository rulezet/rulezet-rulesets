rule TTP_XOR_QUAD_CurrentVersionRun_67f7 {
  strings:
    $key_67f7 = { 34 98 [2] 10 96 [2] 3b ba [2] 15 98 [2] 01 83 [2] 0e 99 [2] 10 84 [2] 12 85 [2] 09 83 [2] 15 84 [2] 09 ab }

  condition:
    any of them
}