rule TTP_XOR_QUAD_CurrentVersionRun_f6a1 {
  strings:
    $key_f6a1 = { a5 ce [2] 81 c0 [2] aa ec [2] 84 ce [2] 90 d5 [2] 9f cf [2] 81 d2 [2] 83 d3 [2] 98 d5 [2] 84 d2 [2] 98 fd }

  condition:
    any of them
}