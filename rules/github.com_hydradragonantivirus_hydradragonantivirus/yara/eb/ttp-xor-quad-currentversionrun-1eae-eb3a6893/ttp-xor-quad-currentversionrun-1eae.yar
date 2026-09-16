rule TTP_XOR_QUAD_CurrentVersionRun_1eae {
  strings:
    $key_1eae = { 4d c1 [2] 69 cf [2] 42 e3 [2] 6c c1 [2] 78 da [2] 77 c0 [2] 69 dd [2] 6b dc [2] 70 da [2] 6c dd [2] 70 f2 }

  condition:
    any of them
}