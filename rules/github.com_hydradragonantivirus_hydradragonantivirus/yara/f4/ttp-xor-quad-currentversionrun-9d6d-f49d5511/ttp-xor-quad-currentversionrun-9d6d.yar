rule TTP_XOR_QUAD_CurrentVersionRun_9d6d {
  strings:
    $key_9d6d = { ce 02 [2] ea 0c [2] c1 20 [2] ef 02 [2] fb 19 [2] f4 03 [2] ea 1e [2] e8 1f [2] f3 19 [2] ef 1e [2] f3 31 }

  condition:
    any of them
}