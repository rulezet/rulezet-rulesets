rule TTP_XOR_QUAD_CurrentVersionRun_9de4 {
  strings:
    $key_9de4 = { ce 8b [2] ea 85 [2] c1 a9 [2] ef 8b [2] fb 90 [2] f4 8a [2] ea 97 [2] e8 96 [2] f3 90 [2] ef 97 [2] f3 b8 }

  condition:
    any of them
}