rule TTP_XOR_QUAD_CurrentVersionRun_9d78 {
  strings:
    $key_9d78 = { ce 17 [2] ea 19 [2] c1 35 [2] ef 17 [2] fb 0c [2] f4 16 [2] ea 0b [2] e8 0a [2] f3 0c [2] ef 0b [2] f3 24 }

  condition:
    any of them
}