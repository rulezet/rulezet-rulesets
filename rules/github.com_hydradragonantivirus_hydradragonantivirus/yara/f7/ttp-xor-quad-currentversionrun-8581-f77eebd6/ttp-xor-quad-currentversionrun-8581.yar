rule TTP_XOR_QUAD_CurrentVersionRun_8581 {
  strings:
    $key_8581 = { d6 ee [2] f2 e0 [2] d9 cc [2] f7 ee [2] e3 f5 [2] ec ef [2] f2 f2 [2] f0 f3 [2] eb f5 [2] f7 f2 [2] eb dd }

  condition:
    any of them
}