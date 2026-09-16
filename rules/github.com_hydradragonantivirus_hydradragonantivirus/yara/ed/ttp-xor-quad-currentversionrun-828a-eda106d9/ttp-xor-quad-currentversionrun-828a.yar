rule TTP_XOR_QUAD_CurrentVersionRun_828a {
  strings:
    $key_828a = { d1 e5 [2] f5 eb [2] de c7 [2] f0 e5 [2] e4 fe [2] eb e4 [2] f5 f9 [2] f7 f8 [2] ec fe [2] f0 f9 [2] ec d6 }

  condition:
    any of them
}