rule TTP_XOR_QUAD_CurrentVersionRun_e29a {
  strings:
    $key_e29a = { b1 f5 [2] 95 fb [2] be d7 [2] 90 f5 [2] 84 ee [2] 8b f4 [2] 95 e9 [2] 97 e8 [2] 8c ee [2] 90 e9 [2] 8c c6 }

  condition:
    any of them
}