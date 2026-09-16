rule TTP_XOR_QUAD_CurrentVersionRun_8244 {
  strings:
    $key_8244 = { d1 2b [2] f5 25 [2] de 09 [2] f0 2b [2] e4 30 [2] eb 2a [2] f5 37 [2] f7 36 [2] ec 30 [2] f0 37 [2] ec 18 }

  condition:
    any of them
}