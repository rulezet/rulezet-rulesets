rule TTP_XOR_QUAD_CurrentVersionRun_a9ae {
  strings:
    $key_a9ae = { fa c1 [2] de cf [2] f5 e3 [2] db c1 [2] cf da [2] c0 c0 [2] de dd [2] dc dc [2] c7 da [2] db dd [2] c7 f2 }

  condition:
    any of them
}