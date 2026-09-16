rule TTP_XOR_QUAD_CurrentVersionRun_9e33 {
  strings:
    $key_9e33 = { cd 5c [2] e9 52 [2] c2 7e [2] ec 5c [2] f8 47 [2] f7 5d [2] e9 40 [2] eb 41 [2] f0 47 [2] ec 40 [2] f0 6f }

  condition:
    any of them
}