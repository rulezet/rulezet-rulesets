rule TTP_XOR_QUAD_CurrentVersionRun_9dff {
  strings:
    $key_9dff = { ce 90 [2] ea 9e [2] c1 b2 [2] ef 90 [2] fb 8b [2] f4 91 [2] ea 8c [2] e8 8d [2] f3 8b [2] ef 8c [2] f3 a3 }

  condition:
    any of them
}