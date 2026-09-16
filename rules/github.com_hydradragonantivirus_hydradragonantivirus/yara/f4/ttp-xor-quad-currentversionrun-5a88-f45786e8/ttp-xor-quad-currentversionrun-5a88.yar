rule TTP_XOR_QUAD_CurrentVersionRun_5a88 {
  strings:
    $key_5a88 = { 09 e7 [2] 2d e9 [2] 06 c5 [2] 28 e7 [2] 3c fc [2] 33 e6 [2] 2d fb [2] 2f fa [2] 34 fc [2] 28 fb [2] 34 d4 }

  condition:
    any of them
}