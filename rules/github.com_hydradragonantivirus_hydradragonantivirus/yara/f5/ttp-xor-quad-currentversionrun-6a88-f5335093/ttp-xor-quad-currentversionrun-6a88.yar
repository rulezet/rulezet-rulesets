rule TTP_XOR_QUAD_CurrentVersionRun_6a88 {
  strings:
    $key_6a88 = { 39 e7 [2] 1d e9 [2] 36 c5 [2] 18 e7 [2] 0c fc [2] 03 e6 [2] 1d fb [2] 1f fa [2] 04 fc [2] 18 fb [2] 04 d4 }

  condition:
    any of them
}