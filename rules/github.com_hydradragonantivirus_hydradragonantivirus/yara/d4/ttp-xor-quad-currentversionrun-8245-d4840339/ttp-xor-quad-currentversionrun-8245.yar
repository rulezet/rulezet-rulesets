rule TTP_XOR_QUAD_CurrentVersionRun_8245 {
  strings:
    $key_8245 = { d1 2a [2] f5 24 [2] de 08 [2] f0 2a [2] e4 31 [2] eb 2b [2] f5 36 [2] f7 37 [2] ec 31 [2] f0 36 [2] ec 19 }

  condition:
    any of them
}