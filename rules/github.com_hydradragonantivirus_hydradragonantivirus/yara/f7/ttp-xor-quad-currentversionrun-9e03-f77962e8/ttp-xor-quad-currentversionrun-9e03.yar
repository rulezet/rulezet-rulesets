rule TTP_XOR_QUAD_CurrentVersionRun_9e03 {
  strings:
    $key_9e03 = { cd 6c [2] e9 62 [2] c2 4e [2] ec 6c [2] f8 77 [2] f7 6d [2] e9 70 [2] eb 71 [2] f0 77 [2] ec 70 [2] f0 5f }

  condition:
    any of them
}