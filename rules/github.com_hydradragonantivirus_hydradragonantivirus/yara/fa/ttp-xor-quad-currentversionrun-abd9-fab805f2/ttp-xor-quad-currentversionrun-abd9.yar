rule TTP_XOR_QUAD_CurrentVersionRun_abd9 {
  strings:
    $key_abd9 = { f8 b6 [2] dc b8 [2] f7 94 [2] d9 b6 [2] cd ad [2] c2 b7 [2] dc aa [2] de ab [2] c5 ad [2] d9 aa [2] c5 85 }

  condition:
    any of them
}