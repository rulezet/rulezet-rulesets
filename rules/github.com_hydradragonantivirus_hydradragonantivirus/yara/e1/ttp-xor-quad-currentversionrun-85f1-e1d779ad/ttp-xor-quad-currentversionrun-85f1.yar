rule TTP_XOR_QUAD_CurrentVersionRun_85f1 {
  strings:
    $key_85f1 = { d6 9e [2] f2 90 [2] d9 bc [2] f7 9e [2] e3 85 [2] ec 9f [2] f2 82 [2] f0 83 [2] eb 85 [2] f7 82 [2] eb ad }

  condition:
    any of them
}