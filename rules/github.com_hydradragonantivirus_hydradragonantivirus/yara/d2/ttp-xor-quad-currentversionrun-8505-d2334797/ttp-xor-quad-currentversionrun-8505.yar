rule TTP_XOR_QUAD_CurrentVersionRun_8505 {
  strings:
    $key_8505 = { d6 6a [2] f2 64 [2] d9 48 [2] f7 6a [2] e3 71 [2] ec 6b [2] f2 76 [2] f0 77 [2] eb 71 [2] f7 76 [2] eb 59 }

  condition:
    any of them
}