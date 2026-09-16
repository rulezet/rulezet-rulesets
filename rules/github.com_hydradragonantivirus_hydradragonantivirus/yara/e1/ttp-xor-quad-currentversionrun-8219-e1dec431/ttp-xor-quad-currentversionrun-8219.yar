rule TTP_XOR_QUAD_CurrentVersionRun_8219 {
  strings:
    $key_8219 = { d1 76 [2] f5 78 [2] de 54 [2] f0 76 [2] e4 6d [2] eb 77 [2] f5 6a [2] f7 6b [2] ec 6d [2] f0 6a [2] ec 45 }

  condition:
    any of them
}