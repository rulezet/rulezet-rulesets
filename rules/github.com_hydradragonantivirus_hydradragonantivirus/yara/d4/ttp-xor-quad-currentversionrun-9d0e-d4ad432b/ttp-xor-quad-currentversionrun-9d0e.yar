rule TTP_XOR_QUAD_CurrentVersionRun_9d0e {
  strings:
    $key_9d0e = { ce 61 [2] ea 6f [2] c1 43 [2] ef 61 [2] fb 7a [2] f4 60 [2] ea 7d [2] e8 7c [2] f3 7a [2] ef 7d [2] f3 52 }

  condition:
    any of them
}