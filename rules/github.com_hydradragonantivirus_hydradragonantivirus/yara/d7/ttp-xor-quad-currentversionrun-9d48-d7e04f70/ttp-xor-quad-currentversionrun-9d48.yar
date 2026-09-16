rule TTP_XOR_QUAD_CurrentVersionRun_9d48 {
  strings:
    $key_9d48 = { ce 27 [2] ea 29 [2] c1 05 [2] ef 27 [2] fb 3c [2] f4 26 [2] ea 3b [2] e8 3a [2] f3 3c [2] ef 3b [2] f3 14 }

  condition:
    any of them
}