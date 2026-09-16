rule TTP_XOR_QUAD_CurrentVersionRun_9dfc {
  strings:
    $key_9dfc = { ce 93 [2] ea 9d [2] c1 b1 [2] ef 93 [2] fb 88 [2] f4 92 [2] ea 8f [2] e8 8e [2] f3 88 [2] ef 8f [2] f3 a0 }

  condition:
    any of them
}