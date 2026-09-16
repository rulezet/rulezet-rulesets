rule TTP_XOR_QUAD_CurrentVersionRun_95c4 {
  strings:
    $key_95c4 = { c6 ab [2] e2 a5 [2] c9 89 [2] e7 ab [2] f3 b0 [2] fc aa [2] e2 b7 [2] e0 b6 [2] fb b0 [2] e7 b7 [2] fb 98 }

  condition:
    any of them
}