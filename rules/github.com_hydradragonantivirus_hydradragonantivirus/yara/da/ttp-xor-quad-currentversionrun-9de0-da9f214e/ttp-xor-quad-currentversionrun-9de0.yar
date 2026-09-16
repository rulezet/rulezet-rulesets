rule TTP_XOR_QUAD_CurrentVersionRun_9de0 {
  strings:
    $key_9de0 = { ce 8f [2] ea 81 [2] c1 ad [2] ef 8f [2] fb 94 [2] f4 8e [2] ea 93 [2] e8 92 [2] f3 94 [2] ef 93 [2] f3 bc }

  condition:
    any of them
}