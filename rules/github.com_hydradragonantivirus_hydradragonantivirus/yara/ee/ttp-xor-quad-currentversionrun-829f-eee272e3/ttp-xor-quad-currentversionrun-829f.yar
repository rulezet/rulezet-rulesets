rule TTP_XOR_QUAD_CurrentVersionRun_829f {
  strings:
    $key_829f = { d1 f0 [2] f5 fe [2] de d2 [2] f0 f0 [2] e4 eb [2] eb f1 [2] f5 ec [2] f7 ed [2] ec eb [2] f0 ec [2] ec c3 }

  condition:
    any of them
}