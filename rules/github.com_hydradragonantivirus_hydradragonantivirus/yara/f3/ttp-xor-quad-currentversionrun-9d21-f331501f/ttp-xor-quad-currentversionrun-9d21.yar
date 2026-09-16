rule TTP_XOR_QUAD_CurrentVersionRun_9d21 {
  strings:
    $key_9d21 = { ce 4e [2] ea 40 [2] c1 6c [2] ef 4e [2] fb 55 [2] f4 4f [2] ea 52 [2] e8 53 [2] f3 55 [2] ef 52 [2] f3 7d }

  condition:
    any of them
}