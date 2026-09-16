rule TTP_XOR_QUAD_CurrentVersionRun_9e6a {
  strings:
    $key_9e6a = { cd 05 [2] e9 0b [2] c2 27 [2] ec 05 [2] f8 1e [2] f7 04 [2] e9 19 [2] eb 18 [2] f0 1e [2] ec 19 [2] f0 36 }

  condition:
    any of them
}