rule TTP_XOR_QUAD_CurrentVersionRun_9dca {
  strings:
    $key_9dca = { ce a5 [2] ea ab [2] c1 87 [2] ef a5 [2] fb be [2] f4 a4 [2] ea b9 [2] e8 b8 [2] f3 be [2] ef b9 [2] f3 96 }

  condition:
    any of them
}