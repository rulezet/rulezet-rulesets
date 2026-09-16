rule TTP_XOR_QUAD_CurrentVersionRun_14bc {
  strings:
    $key_14bc = { 47 d3 [2] 63 dd [2] 48 f1 [2] 66 d3 [2] 72 c8 [2] 7d d2 [2] 63 cf [2] 61 ce [2] 7a c8 [2] 66 cf [2] 7a e0 }

  condition:
    any of them
}