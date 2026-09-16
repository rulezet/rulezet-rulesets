rule TTP_XOR_QUAD_CurrentVersionRun_8576 {
  strings:
    $key_8576 = { d6 19 [2] f2 17 [2] d9 3b [2] f7 19 [2] e3 02 [2] ec 18 [2] f2 05 [2] f0 04 [2] eb 02 [2] f7 05 [2] eb 2a }

  condition:
    any of them
}