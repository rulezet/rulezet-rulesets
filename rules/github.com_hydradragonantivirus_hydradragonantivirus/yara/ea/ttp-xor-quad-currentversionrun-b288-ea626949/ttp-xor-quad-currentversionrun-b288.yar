rule TTP_XOR_QUAD_CurrentVersionRun_b288 {
  strings:
    $key_b288 = { e1 e7 [2] c5 e9 [2] ee c5 [2] c0 e7 [2] d4 fc [2] db e6 [2] c5 fb [2] c7 fa [2] dc fc [2] c0 fb [2] dc d4 }

  condition:
    any of them
}