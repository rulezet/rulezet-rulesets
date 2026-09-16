rule TTP_XOR_QUAD_CurrentVersionRun_27d1 {
  strings:
    $key_27d1 = { 74 be [2] 50 b0 [2] 7b 9c [2] 55 be [2] 41 a5 [2] 4e bf [2] 50 a2 [2] 52 a3 [2] 49 a5 [2] 55 a2 [2] 49 8d }

  condition:
    any of them
}