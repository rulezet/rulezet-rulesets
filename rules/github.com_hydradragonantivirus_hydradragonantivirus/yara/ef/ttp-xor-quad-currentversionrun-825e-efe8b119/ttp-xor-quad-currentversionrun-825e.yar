rule TTP_XOR_QUAD_CurrentVersionRun_825e {
  strings:
    $key_825e = { d1 31 [2] f5 3f [2] de 13 [2] f0 31 [2] e4 2a [2] eb 30 [2] f5 2d [2] f7 2c [2] ec 2a [2] f0 2d [2] ec 02 }

  condition:
    any of them
}