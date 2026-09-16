rule TTP_XOR_QUAD_CurrentVersionRun_9e5c {
  strings:
    $key_9e5c = { cd 33 [2] e9 3d [2] c2 11 [2] ec 33 [2] f8 28 [2] f7 32 [2] e9 2f [2] eb 2e [2] f0 28 [2] ec 2f [2] f0 00 }

  condition:
    any of them
}