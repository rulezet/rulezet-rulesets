rule TTP_XOR_QUAD_CurrentVersionRun_abc4 {
  strings:
    $key_abc4 = { f8 ab [2] dc a5 [2] f7 89 [2] d9 ab [2] cd b0 [2] c2 aa [2] dc b7 [2] de b6 [2] c5 b0 [2] d9 b7 [2] c5 98 }

  condition:
    any of them
}