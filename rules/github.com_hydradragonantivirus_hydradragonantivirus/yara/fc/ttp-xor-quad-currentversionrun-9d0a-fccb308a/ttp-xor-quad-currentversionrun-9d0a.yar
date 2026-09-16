rule TTP_XOR_QUAD_CurrentVersionRun_9d0a {
  strings:
    $key_9d0a = { ce 65 [2] ea 6b [2] c1 47 [2] ef 65 [2] fb 7e [2] f4 64 [2] ea 79 [2] e8 78 [2] f3 7e [2] ef 79 [2] f3 56 }

  condition:
    any of them
}