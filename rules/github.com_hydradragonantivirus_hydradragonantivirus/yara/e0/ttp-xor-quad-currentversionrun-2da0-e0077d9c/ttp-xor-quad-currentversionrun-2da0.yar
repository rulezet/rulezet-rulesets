rule TTP_XOR_QUAD_CurrentVersionRun_2da0 {
  strings:
    $key_2da0 = { 7e cf [2] 5a c1 [2] 71 ed [2] 5f cf [2] 4b d4 [2] 44 ce [2] 5a d3 [2] 58 d2 [2] 43 d4 [2] 5f d3 [2] 43 fc }

  condition:
    any of them
}