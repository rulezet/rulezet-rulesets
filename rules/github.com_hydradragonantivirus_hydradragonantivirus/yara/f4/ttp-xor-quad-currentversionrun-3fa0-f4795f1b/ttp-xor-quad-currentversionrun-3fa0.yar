rule TTP_XOR_QUAD_CurrentVersionRun_3fa0 {
  strings:
    $key_3fa0 = { 6c cf [2] 48 c1 [2] 63 ed [2] 4d cf [2] 59 d4 [2] 56 ce [2] 48 d3 [2] 4a d2 [2] 51 d4 [2] 4d d3 [2] 51 fc }

  condition:
    any of them
}