rule TTP_XOR_QUAD_CurrentVersionRun_5eae {
  strings:
    $key_5eae = { 0d c1 [2] 29 cf [2] 02 e3 [2] 2c c1 [2] 38 da [2] 37 c0 [2] 29 dd [2] 2b dc [2] 30 da [2] 2c dd [2] 30 f2 }

  condition:
    any of them
}