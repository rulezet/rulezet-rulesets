rule TTP_XOR_QUAD_CurrentVersionRun_9bc3 {
  strings:
    $key_9bc3 = { c8 ac [2] ec a2 [2] c7 8e [2] e9 ac [2] fd b7 [2] f2 ad [2] ec b0 [2] ee b1 [2] f5 b7 [2] e9 b0 [2] f5 9f }

  condition:
    any of them
}