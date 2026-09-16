rule TTP_XOR_QUAD_CurrentVersionRun_9e61 {
  strings:
    $key_9e61 = { cd 0e [2] e9 00 [2] c2 2c [2] ec 0e [2] f8 15 [2] f7 0f [2] e9 12 [2] eb 13 [2] f0 15 [2] ec 12 [2] f0 3d }

  condition:
    any of them
}