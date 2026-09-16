rule TTP_XOR_QUAD_CurrentVersionRun_9d35 {
  strings:
    $key_9d35 = { ce 5a [2] ea 54 [2] c1 78 [2] ef 5a [2] fb 41 [2] f4 5b [2] ea 46 [2] e8 47 [2] f3 41 [2] ef 46 [2] f3 69 }

  condition:
    any of them
}