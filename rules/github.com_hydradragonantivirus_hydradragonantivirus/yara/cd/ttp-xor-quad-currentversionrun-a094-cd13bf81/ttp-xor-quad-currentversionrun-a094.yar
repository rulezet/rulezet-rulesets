rule TTP_XOR_QUAD_CurrentVersionRun_a094 {
  strings:
    $key_a094 = { f3 fb [2] d7 f5 [2] fc d9 [2] d2 fb [2] c6 e0 [2] c9 fa [2] d7 e7 [2] d5 e6 [2] ce e0 [2] d2 e7 [2] ce c8 }

  condition:
    any of them
}