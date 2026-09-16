rule TTP_XOR_QUAD_CurrentVersionRun_9e4c {
  strings:
    $key_9e4c = { cd 23 [2] e9 2d [2] c2 01 [2] ec 23 [2] f8 38 [2] f7 22 [2] e9 3f [2] eb 3e [2] f0 38 [2] ec 3f [2] f0 10 }

  condition:
    any of them
}