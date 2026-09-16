rule TTP_XOR_QUAD_CurrentVersionRun_feae {
  strings:
    $key_feae = { ad c1 [2] 89 cf [2] a2 e3 [2] 8c c1 [2] 98 da [2] 97 c0 [2] 89 dd [2] 8b dc [2] 90 da [2] 8c dd [2] 90 f2 }

  condition:
    any of them
}