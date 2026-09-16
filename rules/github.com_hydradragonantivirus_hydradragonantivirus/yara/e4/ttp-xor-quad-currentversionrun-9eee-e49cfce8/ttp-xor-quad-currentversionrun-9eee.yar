rule TTP_XOR_QUAD_CurrentVersionRun_9eee {
  strings:
    $key_9eee = { cd 81 [2] e9 8f [2] c2 a3 [2] ec 81 [2] f8 9a [2] f7 80 [2] e9 9d [2] eb 9c [2] f0 9a [2] ec 9d [2] f0 b2 }

  condition:
    any of them
}