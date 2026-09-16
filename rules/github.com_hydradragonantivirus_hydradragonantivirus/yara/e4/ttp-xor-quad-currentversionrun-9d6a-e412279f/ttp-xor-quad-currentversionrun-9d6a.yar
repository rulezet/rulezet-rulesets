rule TTP_XOR_QUAD_CurrentVersionRun_9d6a {
  strings:
    $key_9d6a = { ce 05 [2] ea 0b [2] c1 27 [2] ef 05 [2] fb 1e [2] f4 04 [2] ea 19 [2] e8 18 [2] f3 1e [2] ef 19 [2] f3 36 }

  condition:
    any of them
}