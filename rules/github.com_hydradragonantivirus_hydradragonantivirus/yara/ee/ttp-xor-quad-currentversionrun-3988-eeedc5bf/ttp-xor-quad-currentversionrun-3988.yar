rule TTP_XOR_QUAD_CurrentVersionRun_3988 {
  strings:
    $key_3988 = { 6a e7 [2] 4e e9 [2] 65 c5 [2] 4b e7 [2] 5f fc [2] 50 e6 [2] 4e fb [2] 4c fa [2] 57 fc [2] 4b fb [2] 57 d4 }

  condition:
    any of them
}