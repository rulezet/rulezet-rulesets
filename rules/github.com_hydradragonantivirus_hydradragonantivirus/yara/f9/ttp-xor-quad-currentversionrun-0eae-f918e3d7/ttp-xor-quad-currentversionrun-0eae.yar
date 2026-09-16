rule TTP_XOR_QUAD_CurrentVersionRun_0eae {
  strings:
    $key_0eae = { 5d c1 [2] 79 cf [2] 52 e3 [2] 7c c1 [2] 68 da [2] 67 c0 [2] 79 dd [2] 7b dc [2] 60 da [2] 7c dd [2] 60 f2 }

  condition:
    any of them
}