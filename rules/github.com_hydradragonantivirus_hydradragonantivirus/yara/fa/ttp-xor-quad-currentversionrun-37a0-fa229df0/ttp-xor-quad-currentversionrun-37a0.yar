rule TTP_XOR_QUAD_CurrentVersionRun_37a0 {
  strings:
    $key_37a0 = { 64 cf [2] 40 c1 [2] 6b ed [2] 45 cf [2] 51 d4 [2] 5e ce [2] 40 d3 [2] 42 d2 [2] 59 d4 [2] 45 d3 [2] 59 fc }

  condition:
    any of them
}