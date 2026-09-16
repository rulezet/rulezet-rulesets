rule TTP_XOR_QUAD_CurrentVersionRun_9e4e {
  strings:
    $key_9e4e = { cd 21 [2] e9 2f [2] c2 03 [2] ec 21 [2] f8 3a [2] f7 20 [2] e9 3d [2] eb 3c [2] f0 3a [2] ec 3d [2] f0 12 }

  condition:
    any of them
}