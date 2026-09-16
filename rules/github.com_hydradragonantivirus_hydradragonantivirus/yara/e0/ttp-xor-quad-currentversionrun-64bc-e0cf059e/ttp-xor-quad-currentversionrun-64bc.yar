rule TTP_XOR_QUAD_CurrentVersionRun_64bc {
  strings:
    $key_64bc = { 37 d3 [2] 13 dd [2] 38 f1 [2] 16 d3 [2] 02 c8 [2] 0d d2 [2] 13 cf [2] 11 ce [2] 0a c8 [2] 16 cf [2] 0a e0 }

  condition:
    any of them
}