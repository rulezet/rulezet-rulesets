rule TTP_XOR_QUAD_CurrentVersionRun_82e7 {
  strings:
    $key_82e7 = { d1 88 [2] f5 86 [2] de aa [2] f0 88 [2] e4 93 [2] eb 89 [2] f5 94 [2] f7 95 [2] ec 93 [2] f0 94 [2] ec bb }

  condition:
    any of them
}