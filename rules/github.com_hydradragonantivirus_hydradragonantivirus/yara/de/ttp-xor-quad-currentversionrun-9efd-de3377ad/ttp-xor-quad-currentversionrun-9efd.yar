rule TTP_XOR_QUAD_CurrentVersionRun_9efd {
  strings:
    $key_9efd = { cd 92 [2] e9 9c [2] c2 b0 [2] ec 92 [2] f8 89 [2] f7 93 [2] e9 8e [2] eb 8f [2] f0 89 [2] ec 8e [2] f0 a1 }

  condition:
    any of them
}