rule TTP_XOR_QUAD_CurrentVersionRun_a794 {
  strings:
    $key_a794 = { f4 fb [2] d0 f5 [2] fb d9 [2] d5 fb [2] c1 e0 [2] ce fa [2] d0 e7 [2] d2 e6 [2] c9 e0 [2] d5 e7 [2] c9 c8 }

  condition:
    any of them
}