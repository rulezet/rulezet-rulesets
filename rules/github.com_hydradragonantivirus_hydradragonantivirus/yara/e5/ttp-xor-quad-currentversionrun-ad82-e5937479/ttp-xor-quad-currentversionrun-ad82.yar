rule TTP_XOR_QUAD_CurrentVersionRun_ad82 {
  strings:
    $key_ad82 = { fe ed [2] da e3 [2] f1 cf [2] df ed [2] cb f6 [2] c4 ec [2] da f1 [2] d8 f0 [2] c3 f6 [2] df f1 [2] c3 de }

  condition:
    any of them
}