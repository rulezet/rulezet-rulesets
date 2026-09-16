rule TTP_XOR_QUAD_CurrentVersionRun_55d1 {
  strings:
    $key_55d1 = { 06 be [2] 22 b0 [2] 09 9c [2] 27 be [2] 33 a5 [2] 3c bf [2] 22 a2 [2] 20 a3 [2] 3b a5 [2] 27 a2 [2] 3b 8d }

  condition:
    any of them
}