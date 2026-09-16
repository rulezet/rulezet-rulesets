rule TTP_XOR_QUAD_CurrentVersionRun_9bc2 {
  strings:
    $key_9bc2 = { c8 ad [2] ec a3 [2] c7 8f [2] e9 ad [2] fd b6 [2] f2 ac [2] ec b1 [2] ee b0 [2] f5 b6 [2] e9 b1 [2] f5 9e }

  condition:
    any of them
}