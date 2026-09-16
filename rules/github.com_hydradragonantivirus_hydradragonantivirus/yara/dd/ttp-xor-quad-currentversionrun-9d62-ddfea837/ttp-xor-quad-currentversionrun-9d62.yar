rule TTP_XOR_QUAD_CurrentVersionRun_9d62 {
  strings:
    $key_9d62 = { ce 0d [2] ea 03 [2] c1 2f [2] ef 0d [2] fb 16 [2] f4 0c [2] ea 11 [2] e8 10 [2] f3 16 [2] ef 11 [2] f3 3e }

  condition:
    any of them
}