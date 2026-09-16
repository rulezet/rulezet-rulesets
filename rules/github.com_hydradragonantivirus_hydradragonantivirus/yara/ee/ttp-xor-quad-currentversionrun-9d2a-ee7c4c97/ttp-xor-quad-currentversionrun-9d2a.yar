rule TTP_XOR_QUAD_CurrentVersionRun_9d2a {
  strings:
    $key_9d2a = { ce 45 [2] ea 4b [2] c1 67 [2] ef 45 [2] fb 5e [2] f4 44 [2] ea 59 [2] e8 58 [2] f3 5e [2] ef 59 [2] f3 76 }

  condition:
    any of them
}