rule TTP_XOR_QUAD_CurrentVersionRun_9e4d {
  strings:
    $key_9e4d = { cd 22 [2] e9 2c [2] c2 00 [2] ec 22 [2] f8 39 [2] f7 23 [2] e9 3e [2] eb 3f [2] f0 39 [2] ec 3e [2] f0 11 }

  condition:
    any of them
}