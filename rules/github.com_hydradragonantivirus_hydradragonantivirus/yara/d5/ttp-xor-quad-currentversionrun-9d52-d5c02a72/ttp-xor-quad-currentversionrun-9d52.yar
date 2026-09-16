rule TTP_XOR_QUAD_CurrentVersionRun_9d52 {
  strings:
    $key_9d52 = { ce 3d [2] ea 33 [2] c1 1f [2] ef 3d [2] fb 26 [2] f4 3c [2] ea 21 [2] e8 20 [2] f3 26 [2] ef 21 [2] f3 0e }

  condition:
    any of them
}