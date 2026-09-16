rule TTP_XOR_QUAD_CurrentVersionRun_4cd1 {
  strings:
    $key_4cd1 = { 1f be [2] 3b b0 [2] 10 9c [2] 3e be [2] 2a a5 [2] 25 bf [2] 3b a2 [2] 39 a3 [2] 22 a5 [2] 3e a2 [2] 22 8d }

  condition:
    any of them
}