rule TTP_XOR_QUAD_CurrentVersionRun_eea0 {
  strings:
    $key_eea0 = { bd cf [2] 99 c1 [2] b2 ed [2] 9c cf [2] 88 d4 [2] 87 ce [2] 99 d3 [2] 9b d2 [2] 80 d4 [2] 9c d3 [2] 80 fc }

  condition:
    any of them
}