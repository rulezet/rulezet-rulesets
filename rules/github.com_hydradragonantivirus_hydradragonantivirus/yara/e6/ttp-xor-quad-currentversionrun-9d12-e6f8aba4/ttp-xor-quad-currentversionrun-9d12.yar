rule TTP_XOR_QUAD_CurrentVersionRun_9d12 {
  strings:
    $key_9d12 = { ce 7d [2] ea 73 [2] c1 5f [2] ef 7d [2] fb 66 [2] f4 7c [2] ea 61 [2] e8 60 [2] f3 66 [2] ef 61 [2] f3 4e }

  condition:
    any of them
}