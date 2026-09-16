rule TTP_XOR_QUAD_CurrentVersionRun_8545 {
  strings:
    $key_8545 = { d6 2a [2] f2 24 [2] d9 08 [2] f7 2a [2] e3 31 [2] ec 2b [2] f2 36 [2] f0 37 [2] eb 31 [2] f7 36 [2] eb 19 }

  condition:
    any of them
}