rule TTP_XOR_QUAD_CurrentVersionRun_d8a1 {
  strings:
    $key_d8a1 = { 8b ce [2] af c0 [2] 84 ec [2] aa ce [2] be d5 [2] b1 cf [2] af d2 [2] ad d3 [2] b6 d5 [2] aa d2 [2] b6 fd }

  condition:
    any of them
}