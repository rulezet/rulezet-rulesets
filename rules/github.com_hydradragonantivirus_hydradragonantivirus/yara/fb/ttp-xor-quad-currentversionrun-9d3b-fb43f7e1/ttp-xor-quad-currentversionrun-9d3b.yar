rule TTP_XOR_QUAD_CurrentVersionRun_9d3b {
  strings:
    $key_9d3b = { ce 54 [2] ea 5a [2] c1 76 [2] ef 54 [2] fb 4f [2] f4 55 [2] ea 48 [2] e8 49 [2] f3 4f [2] ef 48 [2] f3 67 }

  condition:
    any of them
}