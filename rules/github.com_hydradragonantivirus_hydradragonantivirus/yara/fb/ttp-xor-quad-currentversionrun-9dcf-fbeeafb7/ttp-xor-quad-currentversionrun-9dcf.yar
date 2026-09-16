rule TTP_XOR_QUAD_CurrentVersionRun_9dcf {
  strings:
    $key_9dcf = { ce a0 [2] ea ae [2] c1 82 [2] ef a0 [2] fb bb [2] f4 a1 [2] ea bc [2] e8 bd [2] f3 bb [2] ef bc [2] f3 93 }

  condition:
    any of them
}