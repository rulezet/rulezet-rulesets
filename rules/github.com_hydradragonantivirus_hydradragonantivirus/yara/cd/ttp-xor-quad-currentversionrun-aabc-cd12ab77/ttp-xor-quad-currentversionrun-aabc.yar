rule TTP_XOR_QUAD_CurrentVersionRun_aabc {
  strings:
    $key_aabc = { f9 d3 [2] dd dd [2] f6 f1 [2] d8 d3 [2] cc c8 [2] c3 d2 [2] dd cf [2] df ce [2] c4 c8 [2] d8 cf [2] c4 e0 }

  condition:
    any of them
}