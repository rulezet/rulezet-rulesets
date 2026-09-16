rule TTP_XOR_QUAD_CurrentVersionRun_56d1 {
  strings:
    $key_56d1 = { 05 be [2] 21 b0 [2] 0a 9c [2] 24 be [2] 30 a5 [2] 3f bf [2] 21 a2 [2] 23 a3 [2] 38 a5 [2] 24 a2 [2] 38 8d }

  condition:
    any of them
}