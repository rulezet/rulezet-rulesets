rule TTP_XOR_QUAD_CurrentVersionRun_1388 {
  strings:
    $key_1388 = { 40 e7 [2] 64 e9 [2] 4f c5 [2] 61 e7 [2] 75 fc [2] 7a e6 [2] 64 fb [2] 66 fa [2] 7d fc [2] 61 fb [2] 7d d4 }

  condition:
    any of them
}