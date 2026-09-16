rule TTP_XOR_QUAD_CurrentVersionRun_9e7f {
  strings:
    $key_9e7f = { cd 10 [2] e9 1e [2] c2 32 [2] ec 10 [2] f8 0b [2] f7 11 [2] e9 0c [2] eb 0d [2] f0 0b [2] ec 0c [2] f0 23 }

  condition:
    any of them
}