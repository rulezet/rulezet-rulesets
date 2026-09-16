rule TTP_XOR_QUAD_CurrentVersionRun_66d1 {
  strings:
    $key_66d1 = { 35 be [2] 11 b0 [2] 3a 9c [2] 14 be [2] 00 a5 [2] 0f bf [2] 11 a2 [2] 13 a3 [2] 08 a5 [2] 14 a2 [2] 08 8d }

  condition:
    any of them
}