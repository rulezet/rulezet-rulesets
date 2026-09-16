rule TTP_XOR_QUAD_CurrentVersionRun_2688 {
  strings:
    $key_2688 = { 75 e7 [2] 51 e9 [2] 7a c5 [2] 54 e7 [2] 40 fc [2] 4f e6 [2] 51 fb [2] 53 fa [2] 48 fc [2] 54 fb [2] 48 d4 }

  condition:
    any of them
}