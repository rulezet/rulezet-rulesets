rule TTP_XOR_QUAD_CurrentVersionRun_9e26 {
  strings:
    $key_9e26 = { cd 49 [2] e9 47 [2] c2 6b [2] ec 49 [2] f8 52 [2] f7 48 [2] e9 55 [2] eb 54 [2] f0 52 [2] ec 55 [2] f0 7a }

  condition:
    any of them
}