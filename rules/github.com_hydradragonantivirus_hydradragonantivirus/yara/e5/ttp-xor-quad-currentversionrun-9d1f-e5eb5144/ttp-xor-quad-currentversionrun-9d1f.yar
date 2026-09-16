rule TTP_XOR_QUAD_CurrentVersionRun_9d1f {
  strings:
    $key_9d1f = { ce 70 [2] ea 7e [2] c1 52 [2] ef 70 [2] fb 6b [2] f4 71 [2] ea 6c [2] e8 6d [2] f3 6b [2] ef 6c [2] f3 43 }

  condition:
    any of them
}