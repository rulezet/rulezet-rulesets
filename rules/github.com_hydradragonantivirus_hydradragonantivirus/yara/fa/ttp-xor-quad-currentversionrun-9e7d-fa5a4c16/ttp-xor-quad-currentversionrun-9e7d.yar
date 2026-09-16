rule TTP_XOR_QUAD_CurrentVersionRun_9e7d {
  strings:
    $key_9e7d = { cd 12 [2] e9 1c [2] c2 30 [2] ec 12 [2] f8 09 [2] f7 13 [2] e9 0e [2] eb 0f [2] f0 09 [2] ec 0e [2] f0 21 }

  condition:
    any of them
}