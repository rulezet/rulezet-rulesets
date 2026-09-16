rule TTP_XOR_QUAD_CurrentVersionRun_8567 {
  strings:
    $key_8567 = { d6 08 [2] f2 06 [2] d9 2a [2] f7 08 [2] e3 13 [2] ec 09 [2] f2 14 [2] f0 15 [2] eb 13 [2] f7 14 [2] eb 3b }

  condition:
    any of them
}