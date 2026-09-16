rule TTP_XOR_QUAD_CurrentVersionRun_8515 {
  strings:
    $key_8515 = { d6 7a [2] f2 74 [2] d9 58 [2] f7 7a [2] e3 61 [2] ec 7b [2] f2 66 [2] f0 67 [2] eb 61 [2] f7 66 [2] eb 49 }

  condition:
    any of them
}