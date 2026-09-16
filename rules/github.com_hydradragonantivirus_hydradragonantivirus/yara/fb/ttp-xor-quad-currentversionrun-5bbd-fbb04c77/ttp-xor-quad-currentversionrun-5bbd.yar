rule TTP_XOR_QUAD_CurrentVersionRun_5bbd {
  strings:
    $key_5bbd = { 08 d2 [2] 2c dc [2] 07 f0 [2] 29 d2 [2] 3d c9 [2] 32 d3 [2] 2c ce [2] 2e cf [2] 35 c9 [2] 29 ce [2] 35 e1 }

  condition:
    any of them
}