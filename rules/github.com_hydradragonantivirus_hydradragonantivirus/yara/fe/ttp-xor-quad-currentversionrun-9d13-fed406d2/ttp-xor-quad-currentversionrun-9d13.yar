rule TTP_XOR_QUAD_CurrentVersionRun_9d13 {
  strings:
    $key_9d13 = { ce 7c [2] ea 72 [2] c1 5e [2] ef 7c [2] fb 67 [2] f4 7d [2] ea 60 [2] e8 61 [2] f3 67 [2] ef 60 [2] f3 4f }

  condition:
    any of them
}