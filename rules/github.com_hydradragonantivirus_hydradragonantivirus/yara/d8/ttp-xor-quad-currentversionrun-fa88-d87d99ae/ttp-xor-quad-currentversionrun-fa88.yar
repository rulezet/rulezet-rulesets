rule TTP_XOR_QUAD_CurrentVersionRun_fa88 {
  strings:
    $key_fa88 = { a9 e7 [2] 8d e9 [2] a6 c5 [2] 88 e7 [2] 9c fc [2] 93 e6 [2] 8d fb [2] 8f fa [2] 94 fc [2] 88 fb [2] 94 d4 }

  condition:
    any of them
}