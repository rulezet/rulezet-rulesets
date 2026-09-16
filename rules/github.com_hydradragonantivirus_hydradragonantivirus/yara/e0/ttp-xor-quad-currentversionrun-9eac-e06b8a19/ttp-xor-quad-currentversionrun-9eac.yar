rule TTP_XOR_QUAD_CurrentVersionRun_9eac {
  strings:
    $key_9eac = { cd c3 [2] e9 cd [2] c2 e1 [2] ec c3 [2] f8 d8 [2] f7 c2 [2] e9 df [2] eb de [2] f0 d8 [2] ec df [2] f0 f0 }

  condition:
    any of them
}