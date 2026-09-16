rule TTP_XOR_QUAD_CurrentVersionRun_9d7d {
  strings:
    $key_9d7d = { ce 12 [2] ea 1c [2] c1 30 [2] ef 12 [2] fb 09 [2] f4 13 [2] ea 0e [2] e8 0f [2] f3 09 [2] ef 0e [2] f3 21 }

  condition:
    any of them
}