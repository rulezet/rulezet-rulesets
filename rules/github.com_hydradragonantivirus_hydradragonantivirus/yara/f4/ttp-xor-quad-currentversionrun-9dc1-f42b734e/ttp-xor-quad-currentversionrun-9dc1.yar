rule TTP_XOR_QUAD_CurrentVersionRun_9dc1 {
  strings:
    $key_9dc1 = { ce ae [2] ea a0 [2] c1 8c [2] ef ae [2] fb b5 [2] f4 af [2] ea b2 [2] e8 b3 [2] f3 b5 [2] ef b2 [2] f3 9d }

  condition:
    any of them
}