rule TTP_XOR_QUAD_CurrentVersionRun_1888 {
  strings:
    $key_1888 = { 4b e7 [2] 6f e9 [2] 44 c5 [2] 6a e7 [2] 7e fc [2] 71 e6 [2] 6f fb [2] 6d fa [2] 76 fc [2] 6a fb [2] 76 d4 }

  condition:
    any of them
}