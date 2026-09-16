rule TTP_XOR_QUAD_CurrentVersionRun_9d50 {
  strings:
    $key_9d50 = { ce 3f [2] ea 31 [2] c1 1d [2] ef 3f [2] fb 24 [2] f4 3e [2] ea 23 [2] e8 22 [2] f3 24 [2] ef 23 [2] f3 0c }

  condition:
    any of them
}