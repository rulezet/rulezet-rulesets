rule TTP_XOR_QUAD_CurrentVersionRun_3688 {
  strings:
    $key_3688 = { 65 e7 [2] 41 e9 [2] 6a c5 [2] 44 e7 [2] 50 fc [2] 5f e6 [2] 41 fb [2] 43 fa [2] 58 fc [2] 44 fb [2] 58 d4 }

  condition:
    any of them
}