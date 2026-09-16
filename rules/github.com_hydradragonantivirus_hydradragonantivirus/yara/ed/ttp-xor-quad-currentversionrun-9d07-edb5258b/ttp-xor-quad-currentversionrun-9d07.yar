rule TTP_XOR_QUAD_CurrentVersionRun_9d07 {
  strings:
    $key_9d07 = { ce 68 [2] ea 66 [2] c1 4a [2] ef 68 [2] fb 73 [2] f4 69 [2] ea 74 [2] e8 75 [2] f3 73 [2] ef 74 [2] f3 5b }

  condition:
    any of them
}