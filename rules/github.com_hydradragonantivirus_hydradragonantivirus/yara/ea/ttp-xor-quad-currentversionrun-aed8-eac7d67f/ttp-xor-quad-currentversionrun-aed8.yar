rule TTP_XOR_QUAD_CurrentVersionRun_aed8 {
  strings:
    $key_aed8 = { fd b7 [2] d9 b9 [2] f2 95 [2] dc b7 [2] c8 ac [2] c7 b6 [2] d9 ab [2] db aa [2] c0 ac [2] dc ab [2] c0 84 }

  condition:
    any of them
}