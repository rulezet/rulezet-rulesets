rule TTP_XOR_QUAD_CurrentVersionRun_9e9e {
  strings:
    $key_9e9e = { cd f1 [2] e9 ff [2] c2 d3 [2] ec f1 [2] f8 ea [2] f7 f0 [2] e9 ed [2] eb ec [2] f0 ea [2] ec ed [2] f0 c2 }

  condition:
    any of them
}