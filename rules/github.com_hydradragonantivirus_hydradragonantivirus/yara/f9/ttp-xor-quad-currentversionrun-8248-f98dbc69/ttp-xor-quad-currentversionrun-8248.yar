rule TTP_XOR_QUAD_CurrentVersionRun_8248 {
  strings:
    $key_8248 = { d1 27 [2] f5 29 [2] de 05 [2] f0 27 [2] e4 3c [2] eb 26 [2] f5 3b [2] f7 3a [2] ec 3c [2] f0 3b [2] ec 14 }

  condition:
    any of them
}