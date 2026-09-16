rule TTP_XOR_QUAD_CurrentVersionRun_9e2b {
  strings:
    $key_9e2b = { cd 44 [2] e9 4a [2] c2 66 [2] ec 44 [2] f8 5f [2] f7 45 [2] e9 58 [2] eb 59 [2] f0 5f [2] ec 58 [2] f0 77 }

  condition:
    any of them
}