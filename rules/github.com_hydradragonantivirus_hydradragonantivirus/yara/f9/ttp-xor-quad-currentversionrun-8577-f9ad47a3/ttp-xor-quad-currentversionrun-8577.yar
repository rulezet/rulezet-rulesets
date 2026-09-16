rule TTP_XOR_QUAD_CurrentVersionRun_8577 {
  strings:
    $key_8577 = { d6 18 [2] f2 16 [2] d9 3a [2] f7 18 [2] e3 03 [2] ec 19 [2] f2 04 [2] f0 05 [2] eb 03 [2] f7 04 [2] eb 2b }

  condition:
    any of them
}