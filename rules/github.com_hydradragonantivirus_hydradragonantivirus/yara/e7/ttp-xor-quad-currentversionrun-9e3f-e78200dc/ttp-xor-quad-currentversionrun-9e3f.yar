rule TTP_XOR_QUAD_CurrentVersionRun_9e3f {
  strings:
    $key_9e3f = { cd 50 [2] e9 5e [2] c2 72 [2] ec 50 [2] f8 4b [2] f7 51 [2] e9 4c [2] eb 4d [2] f0 4b [2] ec 4c [2] f0 63 }

  condition:
    any of them
}