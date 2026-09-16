rule TTP_XOR_QUAD_CurrentVersionRun_dda0 {
  strings:
    $key_dda0 = { 8e cf [2] aa c1 [2] 81 ed [2] af cf [2] bb d4 [2] b4 ce [2] aa d3 [2] a8 d2 [2] b3 d4 [2] af d3 [2] b3 fc }

  condition:
    any of them
}