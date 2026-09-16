rule TTP_XOR_QUAD_CurrentVersionRun_9d04 {
  strings:
    $key_9d04 = { ce 6b [2] ea 65 [2] c1 49 [2] ef 6b [2] fb 70 [2] f4 6a [2] ea 77 [2] e8 76 [2] f3 70 [2] ef 77 [2] f3 58 }

  condition:
    any of them
}