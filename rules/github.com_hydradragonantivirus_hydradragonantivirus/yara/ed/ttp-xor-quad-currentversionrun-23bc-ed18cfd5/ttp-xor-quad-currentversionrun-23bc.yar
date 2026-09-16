rule TTP_XOR_QUAD_CurrentVersionRun_23bc {
  strings:
    $key_23bc = { 70 d3 [2] 54 dd [2] 7f f1 [2] 51 d3 [2] 45 c8 [2] 4a d2 [2] 54 cf [2] 56 ce [2] 4d c8 [2] 51 cf [2] 4d e0 }

  condition:
    any of them
}