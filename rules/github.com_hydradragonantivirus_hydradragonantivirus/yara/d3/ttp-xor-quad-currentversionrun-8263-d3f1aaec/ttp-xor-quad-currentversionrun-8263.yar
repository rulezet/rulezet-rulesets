rule TTP_XOR_QUAD_CurrentVersionRun_8263 {
  strings:
    $key_8263 = { d1 0c [2] f5 02 [2] de 2e [2] f0 0c [2] e4 17 [2] eb 0d [2] f5 10 [2] f7 11 [2] ec 17 [2] f0 10 [2] ec 3f }

  condition:
    any of them
}