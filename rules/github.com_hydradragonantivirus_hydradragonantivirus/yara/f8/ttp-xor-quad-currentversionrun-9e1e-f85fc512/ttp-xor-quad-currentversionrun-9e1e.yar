rule TTP_XOR_QUAD_CurrentVersionRun_9e1e {
  strings:
    $key_9e1e = { cd 71 [2] e9 7f [2] c2 53 [2] ec 71 [2] f8 6a [2] f7 70 [2] e9 6d [2] eb 6c [2] f0 6a [2] ec 6d [2] f0 42 }

  condition:
    any of them
}