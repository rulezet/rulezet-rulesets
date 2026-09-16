rule TTP_XOR_QUAD_CurrentVersionRun_9d8c {
  strings:
    $key_9d8c = { ce e3 [2] ea ed [2] c1 c1 [2] ef e3 [2] fb f8 [2] f4 e2 [2] ea ff [2] e8 fe [2] f3 f8 [2] ef ff [2] f3 d0 }

  condition:
    any of them
}