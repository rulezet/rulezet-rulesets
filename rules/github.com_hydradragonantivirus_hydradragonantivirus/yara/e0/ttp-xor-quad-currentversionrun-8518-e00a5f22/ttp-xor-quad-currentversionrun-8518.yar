rule TTP_XOR_QUAD_CurrentVersionRun_8518 {
  strings:
    $key_8518 = { d6 77 [2] f2 79 [2] d9 55 [2] f7 77 [2] e3 6c [2] ec 76 [2] f2 6b [2] f0 6a [2] eb 6c [2] f7 6b [2] eb 44 }

  condition:
    any of them
}