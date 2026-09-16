rule TTP_XOR_QUAD_CurrentVersionRun_8274 {
  strings:
    $key_8274 = { d1 1b [2] f5 15 [2] de 39 [2] f0 1b [2] e4 00 [2] eb 1a [2] f5 07 [2] f7 06 [2] ec 00 [2] f0 07 [2] ec 28 }

  condition:
    any of them
}