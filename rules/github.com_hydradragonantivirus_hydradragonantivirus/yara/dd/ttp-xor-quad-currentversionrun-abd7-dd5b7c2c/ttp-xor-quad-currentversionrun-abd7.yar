rule TTP_XOR_QUAD_CurrentVersionRun_abd7 {
  strings:
    $key_abd7 = { f8 b8 [2] dc b6 [2] f7 9a [2] d9 b8 [2] cd a3 [2] c2 b9 [2] dc a4 [2] de a5 [2] c5 a3 [2] d9 a4 [2] c5 8b }

  condition:
    any of them
}