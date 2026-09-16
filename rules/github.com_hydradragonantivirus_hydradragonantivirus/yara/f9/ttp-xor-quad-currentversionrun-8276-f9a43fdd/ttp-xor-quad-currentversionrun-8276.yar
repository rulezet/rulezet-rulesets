rule TTP_XOR_QUAD_CurrentVersionRun_8276 {
  strings:
    $key_8276 = { d1 19 [2] f5 17 [2] de 3b [2] f0 19 [2] e4 02 [2] eb 18 [2] f5 05 [2] f7 04 [2] ec 02 [2] f0 05 [2] ec 2a }

  condition:
    any of them
}