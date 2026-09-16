rule TTP_XOR_QUAD_CurrentVersionRun_8212 {
  strings:
    $key_8212 = { d1 7d [2] f5 73 [2] de 5f [2] f0 7d [2] e4 66 [2] eb 7c [2] f5 61 [2] f7 60 [2] ec 66 [2] f0 61 [2] ec 4e }

  condition:
    any of them
}