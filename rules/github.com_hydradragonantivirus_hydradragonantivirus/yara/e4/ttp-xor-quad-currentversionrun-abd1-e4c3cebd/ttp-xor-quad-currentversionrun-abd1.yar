rule TTP_XOR_QUAD_CurrentVersionRun_abd1 {
  strings:
    $key_abd1 = { f8 be [2] dc b0 [2] f7 9c [2] d9 be [2] cd a5 [2] c2 bf [2] dc a2 [2] de a3 [2] c5 a5 [2] d9 a2 [2] c5 8d }

  condition:
    any of them
}