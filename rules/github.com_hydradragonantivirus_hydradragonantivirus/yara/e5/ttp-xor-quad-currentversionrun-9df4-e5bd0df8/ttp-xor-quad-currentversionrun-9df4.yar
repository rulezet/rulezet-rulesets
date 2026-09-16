rule TTP_XOR_QUAD_CurrentVersionRun_9df4 {
  strings:
    $key_9df4 = { ce 9b [2] ea 95 [2] c1 b9 [2] ef 9b [2] fb 80 [2] f4 9a [2] ea 87 [2] e8 86 [2] f3 80 [2] ef 87 [2] f3 a8 }

  condition:
    any of them
}