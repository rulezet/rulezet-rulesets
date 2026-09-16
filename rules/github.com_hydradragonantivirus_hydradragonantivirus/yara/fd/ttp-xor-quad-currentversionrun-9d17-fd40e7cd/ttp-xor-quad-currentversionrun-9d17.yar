rule TTP_XOR_QUAD_CurrentVersionRun_9d17 {
  strings:
    $key_9d17 = { ce 78 [2] ea 76 [2] c1 5a [2] ef 78 [2] fb 63 [2] f4 79 [2] ea 64 [2] e8 65 [2] f3 63 [2] ef 64 [2] f3 4b }

  condition:
    any of them
}