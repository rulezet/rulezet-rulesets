rule TTP_XOR_QUAD_CurrentVersionRun_79bd {
  strings:
    $key_79bd = { 2a d2 [2] 0e dc [2] 25 f0 [2] 0b d2 [2] 1f c9 [2] 10 d3 [2] 0e ce [2] 0c cf [2] 17 c9 [2] 0b ce [2] 17 e1 }

  condition:
    any of them
}