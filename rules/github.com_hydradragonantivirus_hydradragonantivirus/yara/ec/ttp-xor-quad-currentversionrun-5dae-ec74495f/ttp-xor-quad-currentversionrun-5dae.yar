rule TTP_XOR_QUAD_CurrentVersionRun_5dae {
  strings:
    $key_5dae = { 0e c1 [2] 2a cf [2] 01 e3 [2] 2f c1 [2] 3b da [2] 34 c0 [2] 2a dd [2] 28 dc [2] 33 da [2] 2f dd [2] 33 f2 }

  condition:
    any of them
}