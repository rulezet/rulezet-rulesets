rule TTP_XOR_QUAD_CurrentVersionRun_8227 {
  strings:
    $key_8227 = { d1 48 [2] f5 46 [2] de 6a [2] f0 48 [2] e4 53 [2] eb 49 [2] f5 54 [2] f7 55 [2] ec 53 [2] f0 54 [2] ec 7b }

  condition:
    any of them
}