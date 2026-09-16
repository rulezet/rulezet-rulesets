rule TTP_XOR_QUAD_CurrentVersionRun_9d8d {
  strings:
    $key_9d8d = { ce e2 [2] ea ec [2] c1 c0 [2] ef e2 [2] fb f9 [2] f4 e3 [2] ea fe [2] e8 ff [2] f3 f9 [2] ef fe [2] f3 d1 }

  condition:
    any of them
}