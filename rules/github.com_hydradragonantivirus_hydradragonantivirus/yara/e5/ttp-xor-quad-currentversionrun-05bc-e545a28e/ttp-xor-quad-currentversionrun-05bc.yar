rule TTP_XOR_QUAD_CurrentVersionRun_05bc {
  strings:
    $key_05bc = { 56 d3 [2] 72 dd [2] 59 f1 [2] 77 d3 [2] 63 c8 [2] 6c d2 [2] 72 cf [2] 70 ce [2] 6b c8 [2] 77 cf [2] 6b e0 }

  condition:
    any of them
}