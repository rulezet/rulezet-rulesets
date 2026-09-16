rule TTP_XOR_QUAD_CurrentVersionRun_b688 {
  strings:
    $key_b688 = { e5 e7 [2] c1 e9 [2] ea c5 [2] c4 e7 [2] d0 fc [2] df e6 [2] c1 fb [2] c3 fa [2] d8 fc [2] c4 fb [2] d8 d4 }

  condition:
    any of them
}