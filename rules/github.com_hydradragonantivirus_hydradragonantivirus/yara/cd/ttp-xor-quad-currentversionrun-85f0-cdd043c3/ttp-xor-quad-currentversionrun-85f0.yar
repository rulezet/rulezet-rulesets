rule TTP_XOR_QUAD_CurrentVersionRun_85f0 {
  strings:
    $key_85f0 = { d6 9f [2] f2 91 [2] d9 bd [2] f7 9f [2] e3 84 [2] ec 9e [2] f2 83 [2] f0 82 [2] eb 84 [2] f7 83 [2] eb ac }

  condition:
    any of them
}