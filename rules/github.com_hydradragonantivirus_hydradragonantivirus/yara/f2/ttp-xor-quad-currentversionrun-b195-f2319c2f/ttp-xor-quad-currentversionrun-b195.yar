rule TTP_XOR_QUAD_CurrentVersionRun_b195 {
  strings:
    $key_b195 = { e2 fa [2] c6 f4 [2] ed d8 [2] c3 fa [2] d7 e1 [2] d8 fb [2] c6 e6 [2] c4 e7 [2] df e1 [2] c3 e6 [2] df c9 }

  condition:
    any of them
}