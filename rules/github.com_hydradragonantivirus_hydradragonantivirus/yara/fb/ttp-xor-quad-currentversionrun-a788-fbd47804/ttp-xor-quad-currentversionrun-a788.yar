rule TTP_XOR_QUAD_CurrentVersionRun_a788 {
  strings:
    $key_a788 = { f4 e7 [2] d0 e9 [2] fb c5 [2] d5 e7 [2] c1 fc [2] ce e6 [2] d0 fb [2] d2 fa [2] c9 fc [2] d5 fb [2] c9 d4 }

  condition:
    any of them
}