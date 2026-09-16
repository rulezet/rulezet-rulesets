rule TTP_XOR_QUAD_CurrentVersionRun_9d7e {
  strings:
    $key_9d7e = { ce 11 [2] ea 1f [2] c1 33 [2] ef 11 [2] fb 0a [2] f4 10 [2] ea 0d [2] e8 0c [2] f3 0a [2] ef 0d [2] f3 22 }

  condition:
    any of them
}