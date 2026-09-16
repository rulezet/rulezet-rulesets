rule TTP_XOR_QUAD_CurrentVersionRun_ab82 {
  strings:
    $key_ab82 = { f8 ed [2] dc e3 [2] f7 cf [2] d9 ed [2] cd f6 [2] c2 ec [2] dc f1 [2] de f0 [2] c5 f6 [2] d9 f1 [2] c5 de }

  condition:
    any of them
}