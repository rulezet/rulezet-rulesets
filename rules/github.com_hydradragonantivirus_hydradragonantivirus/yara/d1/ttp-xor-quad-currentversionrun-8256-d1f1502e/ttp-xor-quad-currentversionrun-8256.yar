rule TTP_XOR_QUAD_CurrentVersionRun_8256 {
  strings:
    $key_8256 = { d1 39 [2] f5 37 [2] de 1b [2] f0 39 [2] e4 22 [2] eb 38 [2] f5 25 [2] f7 24 [2] ec 22 [2] f0 25 [2] ec 0a }

  condition:
    any of them
}