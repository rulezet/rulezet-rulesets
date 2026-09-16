rule TTP_XOR_QUAD_CurrentVersionRun_9d29 {
  strings:
    $key_9d29 = { ce 46 [2] ea 48 [2] c1 64 [2] ef 46 [2] fb 5d [2] f4 47 [2] ea 5a [2] e8 5b [2] f3 5d [2] ef 5a [2] f3 75 }

  condition:
    any of them
}