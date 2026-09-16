rule TTP_XOR_QUAD_CurrentVersionRun_8224 {
  strings:
    $key_8224 = { d1 4b [2] f5 45 [2] de 69 [2] f0 4b [2] e4 50 [2] eb 4a [2] f5 57 [2] f7 56 [2] ec 50 [2] f0 57 [2] ec 78 }

  condition:
    any of them
}