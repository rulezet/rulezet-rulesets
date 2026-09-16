rule TTP_XOR_QUAD_CurrentVersionRun_8508 {
  strings:
    $key_8508 = { d6 67 [2] f2 69 [2] d9 45 [2] f7 67 [2] e3 7c [2] ec 66 [2] f2 7b [2] f0 7a [2] eb 7c [2] f7 7b [2] eb 54 }

  condition:
    any of them
}