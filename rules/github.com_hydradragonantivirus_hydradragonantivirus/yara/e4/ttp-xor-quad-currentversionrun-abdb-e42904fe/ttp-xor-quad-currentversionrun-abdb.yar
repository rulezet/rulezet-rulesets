rule TTP_XOR_QUAD_CurrentVersionRun_abdb {
  strings:
    $key_abdb = { f8 b4 [2] dc ba [2] f7 96 [2] d9 b4 [2] cd af [2] c2 b5 [2] dc a8 [2] de a9 [2] c5 af [2] d9 a8 [2] c5 87 }

  condition:
    any of them
}