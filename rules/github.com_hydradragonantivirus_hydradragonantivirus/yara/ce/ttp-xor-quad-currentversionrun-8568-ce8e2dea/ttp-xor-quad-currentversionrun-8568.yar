rule TTP_XOR_QUAD_CurrentVersionRun_8568 {
  strings:
    $key_8568 = { d6 07 [2] f2 09 [2] d9 25 [2] f7 07 [2] e3 1c [2] ec 06 [2] f2 1b [2] f0 1a [2] eb 1c [2] f7 1b [2] eb 34 }

  condition:
    any of them
}