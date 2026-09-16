rule TTP_XOR_QUAD_CurrentVersionRun_9e46 {
  strings:
    $key_9e46 = { cd 29 [2] e9 27 [2] c2 0b [2] ec 29 [2] f8 32 [2] f7 28 [2] e9 35 [2] eb 34 [2] f0 32 [2] ec 35 [2] f0 1a }

  condition:
    any of them
}