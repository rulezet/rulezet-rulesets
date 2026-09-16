rule TTP_XOR_QUAD_CurrentVersionRun_e6a1 {
  strings:
    $key_e6a1 = { b5 ce [2] 91 c0 [2] ba ec [2] 94 ce [2] 80 d5 [2] 8f cf [2] 91 d2 [2] 93 d3 [2] 88 d5 [2] 94 d2 [2] 88 fd }

  condition:
    any of them
}