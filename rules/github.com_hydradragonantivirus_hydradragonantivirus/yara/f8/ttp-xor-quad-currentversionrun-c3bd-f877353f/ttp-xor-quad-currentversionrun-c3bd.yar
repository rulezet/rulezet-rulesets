rule TTP_XOR_QUAD_CurrentVersionRun_c3bd {
  strings:
    $key_c3bd = { 90 d2 [2] b4 dc [2] 9f f0 [2] b1 d2 [2] a5 c9 [2] aa d3 [2] b4 ce [2] b6 cf [2] ad c9 [2] b1 ce [2] ad e1 }

  condition:
    any of them
}