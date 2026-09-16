rule TTP_XOR_QUAD_CurrentVersionRun_9e2a {
  strings:
    $key_9e2a = { cd 45 [2] e9 4b [2] c2 67 [2] ec 45 [2] f8 5e [2] f7 44 [2] e9 59 [2] eb 58 [2] f0 5e [2] ec 59 [2] f0 76 }

  condition:
    any of them
}