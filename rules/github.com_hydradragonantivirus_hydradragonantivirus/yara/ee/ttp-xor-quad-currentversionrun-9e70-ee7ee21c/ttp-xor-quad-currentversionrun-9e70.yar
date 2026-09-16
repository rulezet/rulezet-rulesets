rule TTP_XOR_QUAD_CurrentVersionRun_9e70 {
  strings:
    $key_9e70 = { cd 1f [2] e9 11 [2] c2 3d [2] ec 1f [2] f8 04 [2] f7 1e [2] e9 03 [2] eb 02 [2] f0 04 [2] ec 03 [2] f0 2c }

  condition:
    any of them
}