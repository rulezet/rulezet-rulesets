rule TTP_XOR_QUAD_CurrentVersionRun_9e14 {
  strings:
    $key_9e14 = { cd 7b [2] e9 75 [2] c2 59 [2] ec 7b [2] f8 60 [2] f7 7a [2] e9 67 [2] eb 66 [2] f0 60 [2] ec 67 [2] f0 48 }

  condition:
    any of them
}