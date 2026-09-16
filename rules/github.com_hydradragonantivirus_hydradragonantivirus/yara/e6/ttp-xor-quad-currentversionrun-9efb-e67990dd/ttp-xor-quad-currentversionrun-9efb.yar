rule TTP_XOR_QUAD_CurrentVersionRun_9efb {
  strings:
    $key_9efb = { cd 94 [2] e9 9a [2] c2 b6 [2] ec 94 [2] f8 8f [2] f7 95 [2] e9 88 [2] eb 89 [2] f0 8f [2] ec 88 [2] f0 a7 }

  condition:
    any of them
}