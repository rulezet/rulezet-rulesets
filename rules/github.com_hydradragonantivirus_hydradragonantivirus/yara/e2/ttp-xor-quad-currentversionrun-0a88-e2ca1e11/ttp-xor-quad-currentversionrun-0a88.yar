rule TTP_XOR_QUAD_CurrentVersionRun_0a88 {
  strings:
    $key_0a88 = { 59 e7 [2] 7d e9 [2] 56 c5 [2] 78 e7 [2] 6c fc [2] 63 e6 [2] 7d fb [2] 7f fa [2] 64 fc [2] 78 fb [2] 64 d4 }

  condition:
    any of them
}