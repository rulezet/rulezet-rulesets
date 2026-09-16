rule TTP_XOR_QUAD_CurrentVersionRun_f69a {
  strings:
    $key_f69a = { a5 f5 [2] 81 fb [2] aa d7 [2] 84 f5 [2] 90 ee [2] 9f f4 [2] 81 e9 [2] 83 e8 [2] 98 ee [2] 84 e9 [2] 98 c6 }

  condition:
    any of them
}