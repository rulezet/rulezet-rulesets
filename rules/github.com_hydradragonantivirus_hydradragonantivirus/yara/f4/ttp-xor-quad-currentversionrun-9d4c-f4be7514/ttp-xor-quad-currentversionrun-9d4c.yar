rule TTP_XOR_QUAD_CurrentVersionRun_9d4c {
  strings:
    $key_9d4c = { ce 23 [2] ea 2d [2] c1 01 [2] ef 23 [2] fb 38 [2] f4 22 [2] ea 3f [2] e8 3e [2] f3 38 [2] ef 3f [2] f3 10 }

  condition:
    any of them
}