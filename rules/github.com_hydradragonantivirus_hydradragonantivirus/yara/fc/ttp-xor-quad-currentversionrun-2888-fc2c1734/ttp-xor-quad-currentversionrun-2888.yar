rule TTP_XOR_QUAD_CurrentVersionRun_2888 {
  strings:
    $key_2888 = { 7b e7 [2] 5f e9 [2] 74 c5 [2] 5a e7 [2] 4e fc [2] 41 e6 [2] 5f fb [2] 5d fa [2] 46 fc [2] 5a fb [2] 46 d4 }

  condition:
    any of them
}