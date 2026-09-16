rule TTP_XOR_QUAD_CurrentVersionRun_67d1 {
  strings:
    $key_67d1 = { 34 be [2] 10 b0 [2] 3b 9c [2] 15 be [2] 01 a5 [2] 0e bf [2] 10 a2 [2] 12 a3 [2] 09 a5 [2] 15 a2 [2] 09 8d }

  condition:
    any of them
}