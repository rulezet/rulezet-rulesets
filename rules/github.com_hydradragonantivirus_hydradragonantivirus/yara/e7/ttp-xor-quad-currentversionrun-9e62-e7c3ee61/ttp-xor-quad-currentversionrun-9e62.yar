rule TTP_XOR_QUAD_CurrentVersionRun_9e62 {
  strings:
    $key_9e62 = { cd 0d [2] e9 03 [2] c2 2f [2] ec 0d [2] f8 16 [2] f7 0c [2] e9 11 [2] eb 10 [2] f0 16 [2] ec 11 [2] f0 3e }

  condition:
    any of them
}