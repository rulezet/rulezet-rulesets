rule TTP_XOR_QUAD_CurrentVersionRun_9e08 {
  strings:
    $key_9e08 = { cd 67 [2] e9 69 [2] c2 45 [2] ec 67 [2] f8 7c [2] f7 66 [2] e9 7b [2] eb 7a [2] f0 7c [2] ec 7b [2] f0 54 }

  condition:
    any of them
}