rule TTP_XOR_QUAD_CurrentVersionRun_7388 {
  strings:
    $key_7388 = { 20 e7 [2] 04 e9 [2] 2f c5 [2] 01 e7 [2] 15 fc [2] 1a e6 [2] 04 fb [2] 06 fa [2] 1d fc [2] 01 fb [2] 1d d4 }

  condition:
    any of them
}