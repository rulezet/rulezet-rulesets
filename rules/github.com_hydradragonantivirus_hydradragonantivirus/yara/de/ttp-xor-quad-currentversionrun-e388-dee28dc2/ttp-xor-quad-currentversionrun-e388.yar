rule TTP_XOR_QUAD_CurrentVersionRun_e388 {
  strings:
    $key_e388 = { b0 e7 [2] 94 e9 [2] bf c5 [2] 91 e7 [2] 85 fc [2] 8a e6 [2] 94 fb [2] 96 fa [2] 8d fc [2] 91 fb [2] 8d d4 }

  condition:
    any of them
}