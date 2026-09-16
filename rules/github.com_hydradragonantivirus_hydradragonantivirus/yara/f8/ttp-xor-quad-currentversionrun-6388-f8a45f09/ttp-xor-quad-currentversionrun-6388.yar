rule TTP_XOR_QUAD_CurrentVersionRun_6388 {
  strings:
    $key_6388 = { 30 e7 [2] 14 e9 [2] 3f c5 [2] 11 e7 [2] 05 fc [2] 0a e6 [2] 14 fb [2] 16 fa [2] 0d fc [2] 11 fb [2] 0d d4 }

  condition:
    any of them
}