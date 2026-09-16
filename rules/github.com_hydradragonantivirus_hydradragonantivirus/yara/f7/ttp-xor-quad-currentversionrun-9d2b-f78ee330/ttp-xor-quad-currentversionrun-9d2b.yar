rule TTP_XOR_QUAD_CurrentVersionRun_9d2b {
  strings:
    $key_9d2b = { ce 44 [2] ea 4a [2] c1 66 [2] ef 44 [2] fb 5f [2] f4 45 [2] ea 58 [2] e8 59 [2] f3 5f [2] ef 58 [2] f3 77 }

  condition:
    any of them
}