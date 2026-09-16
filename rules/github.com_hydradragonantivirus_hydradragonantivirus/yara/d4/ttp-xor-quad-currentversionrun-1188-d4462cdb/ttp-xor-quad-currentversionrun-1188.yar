rule TTP_XOR_QUAD_CurrentVersionRun_1188 {
  strings:
    $key_1188 = { 42 e7 [2] 66 e9 [2] 4d c5 [2] 63 e7 [2] 77 fc [2] 78 e6 [2] 66 fb [2] 64 fa [2] 7f fc [2] 63 fb [2] 7f d4 }

  condition:
    any of them
}