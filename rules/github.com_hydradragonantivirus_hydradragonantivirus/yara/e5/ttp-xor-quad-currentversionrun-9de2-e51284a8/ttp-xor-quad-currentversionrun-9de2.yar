rule TTP_XOR_QUAD_CurrentVersionRun_9de2 {
  strings:
    $key_9de2 = { ce 8d [2] ea 83 [2] c1 af [2] ef 8d [2] fb 96 [2] f4 8c [2] ea 91 [2] e8 90 [2] f3 96 [2] ef 91 [2] f3 be }

  condition:
    any of them
}