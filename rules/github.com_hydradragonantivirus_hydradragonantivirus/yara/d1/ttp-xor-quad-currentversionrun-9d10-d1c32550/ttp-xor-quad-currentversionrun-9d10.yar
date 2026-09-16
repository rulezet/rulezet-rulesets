rule TTP_XOR_QUAD_CurrentVersionRun_9d10 {
  strings:
    $key_9d10 = { ce 7f [2] ea 71 [2] c1 5d [2] ef 7f [2] fb 64 [2] f4 7e [2] ea 63 [2] e8 62 [2] f3 64 [2] ef 63 [2] f3 4c }

  condition:
    any of them
}