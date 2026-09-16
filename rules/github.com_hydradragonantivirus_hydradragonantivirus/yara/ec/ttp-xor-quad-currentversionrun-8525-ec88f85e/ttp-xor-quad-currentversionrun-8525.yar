rule TTP_XOR_QUAD_CurrentVersionRun_8525 {
  strings:
    $key_8525 = { d6 4a [2] f2 44 [2] d9 68 [2] f7 4a [2] e3 51 [2] ec 4b [2] f2 56 [2] f0 57 [2] eb 51 [2] f7 56 [2] eb 79 }

  condition:
    any of them
}