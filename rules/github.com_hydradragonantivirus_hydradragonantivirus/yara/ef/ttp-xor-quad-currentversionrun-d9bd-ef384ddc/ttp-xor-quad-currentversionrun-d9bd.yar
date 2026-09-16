rule TTP_XOR_QUAD_CurrentVersionRun_d9bd {
  strings:
    $key_d9bd = { 8a d2 [2] ae dc [2] 85 f0 [2] ab d2 [2] bf c9 [2] b0 d3 [2] ae ce [2] ac cf [2] b7 c9 [2] ab ce [2] b7 e1 }

  condition:
    any of them
}