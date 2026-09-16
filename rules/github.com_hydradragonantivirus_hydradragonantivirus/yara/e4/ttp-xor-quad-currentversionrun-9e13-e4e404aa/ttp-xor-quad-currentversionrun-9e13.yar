rule TTP_XOR_QUAD_CurrentVersionRun_9e13 {
  strings:
    $key_9e13 = { cd 7c [2] e9 72 [2] c2 5e [2] ec 7c [2] f8 67 [2] f7 7d [2] e9 60 [2] eb 61 [2] f0 67 [2] ec 60 [2] f0 4f }

  condition:
    any of them
}