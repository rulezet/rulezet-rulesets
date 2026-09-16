rule TTP_XOR_QUAD_CurrentVersionRun_9d4d {
  strings:
    $key_9d4d = { ce 22 [2] ea 2c [2] c1 00 [2] ef 22 [2] fb 39 [2] f4 23 [2] ea 3e [2] e8 3f [2] f3 39 [2] ef 3e [2] f3 11 }

  condition:
    any of them
}