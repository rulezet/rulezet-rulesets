rule TTP_XOR_QUAD_CurrentVersionRun_9b9d {
  strings:
    $key_9b9d = { c8 f2 [2] ec fc [2] c7 d0 [2] e9 f2 [2] fd e9 [2] f2 f3 [2] ec ee [2] ee ef [2] f5 e9 [2] e9 ee [2] f5 c1 }

  condition:
    any of them
}