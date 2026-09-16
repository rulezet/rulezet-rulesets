rule TTP_XOR_QUAD_CurrentVersionRun_9d0d {
  strings:
    $key_9d0d = { ce 62 [2] ea 6c [2] c1 40 [2] ef 62 [2] fb 79 [2] f4 63 [2] ea 7e [2] e8 7f [2] f3 79 [2] ef 7e [2] f3 51 }

  condition:
    any of them
}