rule TTP_XOR_QUAD_CurrentVersionRun_9ef5 {
  strings:
    $key_9ef5 = { cd 9a [2] e9 94 [2] c2 b8 [2] ec 9a [2] f8 81 [2] f7 9b [2] e9 86 [2] eb 87 [2] f0 81 [2] ec 86 [2] f0 a9 }

  condition:
    any of them
}