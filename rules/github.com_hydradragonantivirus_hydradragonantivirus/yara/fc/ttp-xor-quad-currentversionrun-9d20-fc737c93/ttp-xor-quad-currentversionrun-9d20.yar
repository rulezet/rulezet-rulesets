rule TTP_XOR_QUAD_CurrentVersionRun_9d20 {
  strings:
    $key_9d20 = { ce 4f [2] ea 41 [2] c1 6d [2] ef 4f [2] fb 54 [2] f4 4e [2] ea 53 [2] e8 52 [2] f3 54 [2] ef 53 [2] f3 7c }

  condition:
    any of them
}