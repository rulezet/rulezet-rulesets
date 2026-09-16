rule TTP_XOR_QUAD_CurrentVersionRun_2388 {
  strings:
    $key_2388 = { 70 e7 [2] 54 e9 [2] 7f c5 [2] 51 e7 [2] 45 fc [2] 4a e6 [2] 54 fb [2] 56 fa [2] 4d fc [2] 51 fb [2] 4d d4 }

  condition:
    any of them
}