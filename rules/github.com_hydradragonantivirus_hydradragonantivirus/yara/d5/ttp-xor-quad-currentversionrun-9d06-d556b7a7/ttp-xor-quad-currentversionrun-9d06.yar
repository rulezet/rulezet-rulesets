rule TTP_XOR_QUAD_CurrentVersionRun_9d06 {
  strings:
    $key_9d06 = { ce 69 [2] ea 67 [2] c1 4b [2] ef 69 [2] fb 72 [2] f4 68 [2] ea 75 [2] e8 74 [2] f3 72 [2] ef 75 [2] f3 5a }

  condition:
    any of them
}