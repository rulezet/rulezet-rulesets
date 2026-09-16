rule TTP_XOR_QUAD_CurrentVersionRun_a9d9 {
  strings:
    $key_a9d9 = { fa b6 [2] de b8 [2] f5 94 [2] db b6 [2] cf ad [2] c0 b7 [2] de aa [2] dc ab [2] c7 ad [2] db aa [2] c7 85 }

  condition:
    any of them
}