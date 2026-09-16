rule TTP_XOR_QUAD_CurrentVersionRun_9d01 {
  strings:
    $key_9d01 = { ce 6e [2] ea 60 [2] c1 4c [2] ef 6e [2] fb 75 [2] f4 6f [2] ea 72 [2] e8 73 [2] f3 75 [2] ef 72 [2] f3 5d }

  condition:
    any of them
}