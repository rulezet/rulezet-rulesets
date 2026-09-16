rule TTP_XOR_QUAD_CurrentVersionRun_9d30 {
  strings:
    $key_9d30 = { ce 5f [2] ea 51 [2] c1 7d [2] ef 5f [2] fb 44 [2] f4 5e [2] ea 43 [2] e8 42 [2] f3 44 [2] ef 43 [2] f3 6c }

  condition:
    any of them
}