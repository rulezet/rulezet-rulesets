rule TTP_XOR_QUAD_CurrentVersionRun_9d24 {
  strings:
    $key_9d24 = { ce 4b [2] ea 45 [2] c1 69 [2] ef 4b [2] fb 50 [2] f4 4a [2] ea 57 [2] e8 56 [2] f3 50 [2] ef 57 [2] f3 78 }

  condition:
    any of them
}