rule TTP_XOR_QUAD_CurrentVersionRun_8209 {
  strings:
    $key_8209 = { d1 66 [2] f5 68 [2] de 44 [2] f0 66 [2] e4 7d [2] eb 67 [2] f5 7a [2] f7 7b [2] ec 7d [2] f0 7a [2] ec 55 }

  condition:
    any of them
}