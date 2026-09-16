rule TTP_XOR_QUAD_CurrentVersionRun_b694 {
  strings:
    $key_b694 = { e5 fb [2] c1 f5 [2] ea d9 [2] c4 fb [2] d0 e0 [2] df fa [2] c1 e7 [2] c3 e6 [2] d8 e0 [2] c4 e7 [2] d8 c8 }

  condition:
    any of them
}