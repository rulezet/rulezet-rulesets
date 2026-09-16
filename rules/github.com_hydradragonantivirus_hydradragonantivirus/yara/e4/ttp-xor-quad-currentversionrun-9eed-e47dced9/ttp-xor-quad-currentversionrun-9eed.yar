rule TTP_XOR_QUAD_CurrentVersionRun_9eed {
  strings:
    $key_9eed = { cd 82 [2] e9 8c [2] c2 a0 [2] ec 82 [2] f8 99 [2] f7 83 [2] e9 9e [2] eb 9f [2] f0 99 [2] ec 9e [2] f0 b1 }

  condition:
    any of them
}