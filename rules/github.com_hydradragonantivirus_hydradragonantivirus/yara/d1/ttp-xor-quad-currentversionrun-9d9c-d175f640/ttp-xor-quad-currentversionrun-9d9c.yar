rule TTP_XOR_QUAD_CurrentVersionRun_9d9c {
  strings:
    $key_9d9c = { ce f3 [2] ea fd [2] c1 d1 [2] ef f3 [2] fb e8 [2] f4 f2 [2] ea ef [2] e8 ee [2] f3 e8 [2] ef ef [2] f3 c0 }

  condition:
    any of them
}