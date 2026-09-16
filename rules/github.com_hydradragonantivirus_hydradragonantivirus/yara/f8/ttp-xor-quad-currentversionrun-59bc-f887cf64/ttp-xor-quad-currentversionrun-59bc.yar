rule TTP_XOR_QUAD_CurrentVersionRun_59bc {
  strings:
    $key_59bc = { 0a d3 [2] 2e dd [2] 05 f1 [2] 2b d3 [2] 3f c8 [2] 30 d2 [2] 2e cf [2] 2c ce [2] 37 c8 [2] 2b cf [2] 37 e0 }

  condition:
    any of them
}