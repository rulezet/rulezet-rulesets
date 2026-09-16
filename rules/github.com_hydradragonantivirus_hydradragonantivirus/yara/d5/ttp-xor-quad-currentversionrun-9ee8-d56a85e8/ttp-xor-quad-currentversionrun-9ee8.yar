rule TTP_XOR_QUAD_CurrentVersionRun_9ee8 {
  strings:
    $key_9ee8 = { cd 87 [2] e9 89 [2] c2 a5 [2] ec 87 [2] f8 9c [2] f7 86 [2] e9 9b [2] eb 9a [2] f0 9c [2] ec 9b [2] f0 b4 }

  condition:
    any of them
}