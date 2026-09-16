rule TTP_XOR_QUAD_CurrentVersionRun_9def {
  strings:
    $key_9def = { ce 80 [2] ea 8e [2] c1 a2 [2] ef 80 [2] fb 9b [2] f4 81 [2] ea 9c [2] e8 9d [2] f3 9b [2] ef 9c [2] f3 b3 }

  condition:
    any of them
}