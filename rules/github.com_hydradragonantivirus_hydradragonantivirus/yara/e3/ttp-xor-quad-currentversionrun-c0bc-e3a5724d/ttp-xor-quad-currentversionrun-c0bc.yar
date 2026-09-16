rule TTP_XOR_QUAD_CurrentVersionRun_c0bc {
  strings:
    $key_c0bc = { 93 d3 [2] b7 dd [2] 9c f1 [2] b2 d3 [2] a6 c8 [2] a9 d2 [2] b7 cf [2] b5 ce [2] ae c8 [2] b2 cf [2] ae e0 }

  condition:
    any of them
}