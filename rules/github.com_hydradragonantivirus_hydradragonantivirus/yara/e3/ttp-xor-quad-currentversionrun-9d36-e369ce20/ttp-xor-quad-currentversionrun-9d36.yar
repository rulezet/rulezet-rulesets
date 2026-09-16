rule TTP_XOR_QUAD_CurrentVersionRun_9d36 {
  strings:
    $key_9d36 = { ce 59 [2] ea 57 [2] c1 7b [2] ef 59 [2] fb 42 [2] f4 58 [2] ea 45 [2] e8 44 [2] f3 42 [2] ef 45 [2] f3 6a }

  condition:
    any of them
}