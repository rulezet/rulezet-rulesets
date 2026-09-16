rule TTP_XOR_QUAD_CurrentVersionRun_820b {
  strings:
    $key_820b = { d1 64 [2] f5 6a [2] de 46 [2] f0 64 [2] e4 7f [2] eb 65 [2] f5 78 [2] f7 79 [2] ec 7f [2] f0 78 [2] ec 57 }

  condition:
    any of them
}