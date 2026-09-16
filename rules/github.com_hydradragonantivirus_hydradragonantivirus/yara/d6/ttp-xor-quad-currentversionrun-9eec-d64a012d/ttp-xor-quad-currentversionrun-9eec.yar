rule TTP_XOR_QUAD_CurrentVersionRun_9eec {
  strings:
    $key_9eec = { cd 83 [2] e9 8d [2] c2 a1 [2] ec 83 [2] f8 98 [2] f7 82 [2] e9 9f [2] eb 9e [2] f0 98 [2] ec 9f [2] f0 b0 }

  condition:
    any of them
}