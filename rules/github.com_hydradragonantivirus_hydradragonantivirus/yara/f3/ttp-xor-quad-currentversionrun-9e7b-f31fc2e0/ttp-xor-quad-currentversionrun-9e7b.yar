rule TTP_XOR_QUAD_CurrentVersionRun_9e7b {
  strings:
    $key_9e7b = { cd 14 [2] e9 1a [2] c2 36 [2] ec 14 [2] f8 0f [2] f7 15 [2] e9 08 [2] eb 09 [2] f0 0f [2] ec 08 [2] f0 27 }

  condition:
    any of them
}