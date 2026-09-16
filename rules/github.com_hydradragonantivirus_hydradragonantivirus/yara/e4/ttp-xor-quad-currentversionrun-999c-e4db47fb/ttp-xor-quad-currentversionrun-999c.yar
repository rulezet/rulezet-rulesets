rule TTP_XOR_QUAD_CurrentVersionRun_999c {
  strings:
    $key_999c = { ca f3 [2] ee fd [2] c5 d1 [2] eb f3 [2] ff e8 [2] f0 f2 [2] ee ef [2] ec ee [2] f7 e8 [2] eb ef [2] f7 c0 }

  condition:
    any of them
}