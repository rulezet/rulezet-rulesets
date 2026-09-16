rule TTP_XOR_QUAD_CurrentVersionRun_9bc7 {
  strings:
    $key_9bc7 = { c8 a8 [2] ec a6 [2] c7 8a [2] e9 a8 [2] fd b3 [2] f2 a9 [2] ec b4 [2] ee b5 [2] f5 b3 [2] e9 b4 [2] f5 9b }

  condition:
    any of them
}