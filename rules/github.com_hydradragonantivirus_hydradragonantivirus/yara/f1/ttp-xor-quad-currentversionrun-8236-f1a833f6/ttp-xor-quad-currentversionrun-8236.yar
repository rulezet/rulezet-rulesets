rule TTP_XOR_QUAD_CurrentVersionRun_8236 {
  strings:
    $key_8236 = { d1 59 [2] f5 57 [2] de 7b [2] f0 59 [2] e4 42 [2] eb 58 [2] f5 45 [2] f7 44 [2] ec 42 [2] f0 45 [2] ec 6a }

  condition:
    any of them
}