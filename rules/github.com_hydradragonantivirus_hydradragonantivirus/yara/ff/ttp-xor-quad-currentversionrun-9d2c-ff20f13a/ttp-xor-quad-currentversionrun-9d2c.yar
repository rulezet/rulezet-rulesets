rule TTP_XOR_QUAD_CurrentVersionRun_9d2c {
  strings:
    $key_9d2c = { ce 43 [2] ea 4d [2] c1 61 [2] ef 43 [2] fb 58 [2] f4 42 [2] ea 5f [2] e8 5e [2] f3 58 [2] ef 5f [2] f3 70 }

  condition:
    any of them
}