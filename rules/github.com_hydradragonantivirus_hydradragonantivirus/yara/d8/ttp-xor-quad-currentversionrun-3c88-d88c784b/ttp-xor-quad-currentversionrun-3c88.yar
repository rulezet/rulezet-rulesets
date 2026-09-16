rule TTP_XOR_QUAD_CurrentVersionRun_3c88 {
  strings:
    $key_3c88 = { 6f e7 [2] 4b e9 [2] 60 c5 [2] 4e e7 [2] 5a fc [2] 55 e6 [2] 4b fb [2] 49 fa [2] 52 fc [2] 4e fb [2] 52 d4 }

  condition:
    any of them
}