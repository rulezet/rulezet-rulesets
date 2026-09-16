rule TTP_XOR_QUAD_CurrentVersionRun_c3a0 {
  strings:
    $key_c3a0 = { 90 cf [2] b4 c1 [2] 9f ed [2] b1 cf [2] a5 d4 [2] aa ce [2] b4 d3 [2] b6 d2 [2] ad d4 [2] b1 d3 [2] ad fc }

  condition:
    any of them
}