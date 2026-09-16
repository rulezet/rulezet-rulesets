rule TTP_XOR_QUAD_CurrentVersionRun_9e8c {
  strings:
    $key_9e8c = { cd e3 [2] e9 ed [2] c2 c1 [2] ec e3 [2] f8 f8 [2] f7 e2 [2] e9 ff [2] eb fe [2] f0 f8 [2] ec ff [2] f0 d0 }

  condition:
    any of them
}