rule TTP_XOR_QUAD_CurrentVersionRun_9df1 {
  strings:
    $key_9df1 = { ce 9e [2] ea 90 [2] c1 bc [2] ef 9e [2] fb 85 [2] f4 9f [2] ea 82 [2] e8 83 [2] f3 85 [2] ef 82 [2] f3 ad }

  condition:
    any of them
}