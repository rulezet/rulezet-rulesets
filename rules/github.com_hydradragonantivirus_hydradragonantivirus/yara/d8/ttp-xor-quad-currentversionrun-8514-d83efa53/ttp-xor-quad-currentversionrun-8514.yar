rule TTP_XOR_QUAD_CurrentVersionRun_8514 {
  strings:
    $key_8514 = { d6 7b [2] f2 75 [2] d9 59 [2] f7 7b [2] e3 60 [2] ec 7a [2] f2 67 [2] f0 66 [2] eb 60 [2] f7 67 [2] eb 48 }

  condition:
    any of them
}