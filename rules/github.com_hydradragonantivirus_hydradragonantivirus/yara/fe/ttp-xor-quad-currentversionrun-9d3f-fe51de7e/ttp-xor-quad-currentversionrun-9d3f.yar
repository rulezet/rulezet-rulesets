rule TTP_XOR_QUAD_CurrentVersionRun_9d3f {
  strings:
    $key_9d3f = { ce 50 [2] ea 5e [2] c1 72 [2] ef 50 [2] fb 4b [2] f4 51 [2] ea 4c [2] e8 4d [2] f3 4b [2] ef 4c [2] f3 63 }

  condition:
    any of them
}